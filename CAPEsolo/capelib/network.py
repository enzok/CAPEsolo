"""Host-side processing of a network capture taken outside the guest.

CAPEsolo does not capture traffic itself, so the pcapng is supplied by the user. The TLS
secrets do come out of the analysis, from two places that write different formats:

  * "tlsdump/tlsdump.log" - capemon injected into lsass, covering Schannel. TLS 1.3
    secrets are already NSS SSLKEYLOGFILE lines, but TLS 1.2 master secrets are written in
    capemon's own "client_random: X, server_random: Y, master_secret: Z" form, which no
    other tool reads. BuildKeyLog converts those to NSS CLIENT_RANDOM lines.
  * "aux_/sslkeylogfile/sslkeys.log" - the sslkeylogfile auxiliary module, covering
    anything that honours the SSLKEYLOGFILE environment variable. Already NSS format.

The merged keylog is what makes an otherwise opaque capture readable, so it is written out
next to the analysis for Wireshark to load as well.
"""

import logging
import mmap
import struct
from collections import Counter
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path

from .path_utils import path_exists

log = logging.getLogger(__name__)

TLSDUMP_LOG = "tlsdump/tlsdump.log"
SSLKEYLOG_LOG = "aux_/sslkeylogfile/sslkeys.log"
KEYLOG_NAME = "keylog.txt"

# Labels the NSS key log format defines. capemon emits the handshake/traffic/exporter ones
# for TLS 1.3 and we synthesise CLIENT_RANDOM for its TLS 1.2 lines.
NSS_LABELS = frozenset(
    (
        "CLIENT_RANDOM",
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EARLY_EXPORTER_SECRET",
        "EXPORTER_SECRET",
        "RSA",
    )
)

# pcapng block types we read. Anything else is skipped by length.
BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_SPB = 0x00000003
BLOCK_EPB = 0x00000006

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100

IP_TCP = 6
IP_UDP = 17

# A capture of a full detonation is large and every packet costs a row, so the walk stops
# rather than hanging the UI on a multi-gigabyte file.
MAX_PACKETS = 200000


def FormatTime(timestamp):
    """Wall clock, so a row can be lined up against the analysis log.

    Defined here rather than in the panel because the prebuilt detail text needs it too, and
    two copies drifted apart at once: the grid showed a time of day while the detail beneath
    it showed a raw epoch value for the same packet.
    """
    if not timestamp:
        return ""

    try:
        return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
    except (OSError, OverflowError, ValueError):
        return f"{timestamp:.6f}"


def NormaliseSecretLine(line):
    """Turn one line of either secrets file into an NSS key log line.

    Returns None for anything unrecognised, so a debug line or a partially written record
    cannot corrupt the merged log - Wireshark stops at the first line it cannot parse.
    """
    text = line.strip()
    if not text or text.startswith("#"):
        return None

    # capemon's TLS 1.2 form. server_random is carried but the NSS format has no field for
    # it: the client random alone identifies the session.
    if text.startswith("client_random:"):
        parts = dict()
        for chunk in text.split(","):
            key, _, value = chunk.partition(":")
            parts[key.strip()] = value.strip()

        client = parts.get("client_random", "")
        secret = parts.get("master_secret", "")
        if client and secret and not _PlaceholderSecret(secret):
            return f"CLIENT_RANDOM {client} {secret}"

        return None

    fields = text.split()
    if len(fields) == 3 and fields[0] in NSS_LABELS:
        if _PlaceholderSecret(fields[2]):
            return None

        return text

    return None


def _PlaceholderSecret(secret):
    """Whether a secret is an all-zero placeholder rather than a captured key.

    A record can be written before the secret is available, leaving zeros behind. CAPEv2
    drops these in modules/processing/decryptpcap.py for the same reason: kept, they look
    like a usable key for a session and make it report as decryptable when it is not.
    """
    return not secret.strip("0")


def BuildKeyLog(analysisDir, write=True):
    """Merge the analysis TLS secrets into a single NSS key log.

    @return: dict describing what was found and where it was written.
    """
    output = {
        "path": "",
        "lines": [],
        "labels": {},
        "client_randoms": set(),
        "sources": {},
        "skipped": 0,
    }

    seen = set()
    lines = []
    skipped = 0
    for relPath in (TLSDUMP_LOG, SSLKEYLOG_LOG):
        source = Path(analysisDir) / relPath
        found = 0
        if not path_exists(str(source)):
            output["sources"][relPath] = None
            continue

        try:
            raw = source.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Could not read TLS secrets from %s: %s", source, e)
            output["sources"][relPath] = None
            continue

        for line in raw.splitlines():
            entry = NormaliseSecretLine(line)
            if entry is None:
                # Comments are part of the format, so only genuinely unrecognised content
                # counts here - this number is meant to mean "secrets we could not use".
                text = line.strip()
                if text and not text.startswith("#"):
                    skipped += 1
                continue

            if entry in seen:
                continue

            seen.add(entry)
            lines.append(entry)
            found += 1

        output["sources"][relPath] = found

    output["lines"] = lines
    output["skipped"] = skipped
    output["labels"] = dict(Counter(entry.split()[0] for entry in lines))
    output["client_randoms"] = {entry.split()[1].lower() for entry in lines}

    if write and lines:
        # Alongside the secrets it was built from, so it travels with the analysis.
        target = Path(analysisDir) / "tlsdump" / KEYLOG_NAME
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            output["path"] = str(target)
        except OSError as e:
            log.warning("Could not write merged key log to %s: %s", target, e)

    return output


def _ReadOptions(body, offset, little):
    """Walk a pcapng option list, returning {code: value}."""
    options = {}
    fmt = "<HH" if little else ">HH"
    while offset + 4 <= len(body):
        code, length = struct.unpack_from(fmt, body, offset)
        offset += 4
        if code == 0:
            break
        options[code] = body[offset : offset + length]
        # Options are padded to a 4 byte boundary.
        offset += length + (-length % 4)

    return options


def _TimestampResolution(options):
    """if_tsresol (option 9); the default is microseconds.

    The high bit selects a power of two rather than a power of ten. That form is rare but
    silently makes every timestamp wrong by orders of magnitude if ignored.
    """
    raw = options.get(9)
    if not raw:
        return 1000000.0

    value = raw[0]
    if value & 0x80:
        return float(2 ** (value & 0x7F))

    return float(10**value)


@contextmanager
def _MappedCapture(pcapPath):
    """Map a capture read-only rather than reading it onto the heap.

    A whole-packet capture of a real detonation runs to hundreds of megabytes or more, and
    reading it with read_bytes() put every byte in memory at once - a multi-gigabyte capture
    simply failed. Mapping also removes a second full read: ParseCapture used to read the file
    to identify it and then hand the path to ParsePcapng, which read it all over again.

    Slices taken from the map are ordinary bytes copies, so frames stay valid after it closes.
    """
    with open(pcapPath, "rb") as handle:
        try:
            mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            # An empty file cannot be mapped, and has nothing to read anyway.
            yield b""
            return

        try:
            yield mapped
        finally:
            mapped.close()


def _IterPcapngBuffer(data, warnings, maxPackets):
    """Yield (timestamp, frame) from a mapped pcapng, one frame at a time."""
    little = True
    divisor = 1000000.0
    offset = 0
    count = 0

    while offset + 12 <= len(data):
        blockType = struct.unpack_from("<I" if little else ">I", data, offset)[0]
        if blockType == BLOCK_SHB:
            # The byte order magic sits inside the section header, so endianness has to be
            # settled from it before any other field of this section is read.
            magic = struct.unpack_from("<I", data, offset + 8)[0]
            if magic == 0x1A2B3C4D:
                little = True
            elif magic == 0x4D3C2B1A:
                little = False
            else:
                warnings.append("Not a pcapng file: section header magic missing.")
                return

        endian = "<" if little else ">"
        blockLength = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
        if blockLength < 12 or offset + blockLength > len(data):
            warnings.append(f"Truncated block at offset {offset}; stopped reading.")
            return

        body = data[offset + 8 : offset + blockLength - 4]

        if blockType == BLOCK_IDB and len(body) >= 8:
            linkType = struct.unpack_from(f"{endian}H", body, 0)[0]
            divisor = _TimestampResolution(_ReadOptions(body, 8, little))
            if linkType != 1:
                warnings.append(
                    f"Interface link type is {linkType}, not Ethernet; frames may not decode."
                )
        elif blockType == BLOCK_EPB and len(body) >= 20:
            tsHigh, tsLow, capLen = struct.unpack_from(f"{endian}III", body, 4)
            yield ((tsHigh << 32) | tsLow) / divisor, body[20 : 20 + capLen]
            count += 1
        elif blockType == BLOCK_SPB and len(body) >= 4:
            # No timestamp in a simple packet block, and no captured length either: the
            # frame runs to the end of the block.
            yield 0.0, body[4:]
            count += 1

        if maxPackets is not None and count >= maxPackets:
            warnings.append(f"Stopped after {maxPackets} packets; the capture holds more.")
            return

        offset += blockLength


def _IterClassicBuffer(data, warnings, maxPackets):
    """Yield (timestamp, frame) from a mapped classic libpcap file."""
    if len(data) < 24:
        warnings.append("File is too short to be a libpcap file.")
        return

    magic = struct.unpack_from(">I", data, 0)[0]
    # The magic encodes both byte order and whether timestamps are micro or nanoseconds.
    if magic == 0xA1B2C3D4:
        endian, divisor = ">", 1000000.0
    elif magic == 0xD4C3B2A1:
        endian, divisor = "<", 1000000.0
    elif magic == 0xA1B23C4D:
        endian, divisor = ">", 1000000000.0
    elif magic == 0x4D3CB2A1:
        endian, divisor = "<", 1000000000.0
    else:
        warnings.append("Not a libpcap file: unrecognised magic number.")
        return

    linkType = struct.unpack_from(f"{endian}I", data, 20)[0]
    if linkType != 1:
        warnings.append(
            f"Interface link type is {linkType}, not Ethernet; frames may not decode."
        )

    offset = 24
    count = 0
    while offset + 16 <= len(data):
        seconds, fraction, capLen, _ = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if capLen > len(data) - offset:
            warnings.append(f"Truncated packet record at offset {offset}; stopped reading.")
            return

        yield seconds + fraction / divisor, data[offset : offset + capLen]
        offset += capLen
        count += 1
        if maxPackets is not None and count >= maxPackets:
            warnings.append(f"Stopped after {maxPackets} packets; the capture holds more.")
            return


def IterCapture(pcapPath, warnings=None, maxPackets=None):
    """Yield (timestamp, frame) for every packet, holding one frame at a time.

    maxPackets=None reads the whole capture. NormalisePcap wants that: its output is the file
    the decrypter reads, so a cap there would silently drop the later streams. ParseCapture
    caps instead, because its result becomes a table of rows.

    Warnings are appended to the caller's list, since a generator cannot return them.
    """
    if warnings is None:
        warnings = []

    try:
        with _MappedCapture(pcapPath) as data:
            if len(data) < 24:
                warnings.append("File is too short to be a capture.")
                return

            if data[:4] == b"\x0a\x0d\x0d\x0a":
                yield from _IterPcapngBuffer(data, warnings, maxPackets)
            else:
                yield from _IterClassicBuffer(data, warnings, maxPackets)
    except OSError as e:
        warnings.append(f"Could not read {pcapPath}: {e}")


def ParsePcapng(pcapPath, maxPackets=MAX_PACKETS):
    """Walk a pcapng file into a list of (timestamp, frame) tuples.

    @return: packets, warnings
    """
    warnings = []
    try:
        with _MappedCapture(pcapPath) as data:
            if len(data) < 12:
                return [], ["File is too short to be a pcapng."]

            return list(_IterPcapngBuffer(data, warnings, maxPackets)), warnings
    except OSError as e:
        return [], [f"Could not read {pcapPath}: {e}"]


def _ClassicPcapHeader(snaplen=262144):
    """Classic libpcap global header, little endian, microsecond timestamps, Ethernet."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1)


# A synthetic Ethernet header for frames captured without one. Locally administered
# all-zero MACs, so it is obvious in a dissector that these were added rather than captured.
_SYNTHETIC_ETHERNET = b"\x00" * 12


def NormalisePcap(pcapPath, outPath, maxPackets=None):
    """Rewrite a capture as a classic pcap that a dpkt-based reader can dissect.

    Three things have to be fixed for tools built on libpcap semantics:

      * pcapng is not readable by httpreplay at all ("Currently we don't support PCAP-NG
        files"), and pktmon's etl2pcap only emits pcapng, so a conversion is unavoidable.
      * A classic pcap declares ONE link type for the whole file, but a pktmon capture mixes
        Ethernet frames with bare IP ones. The bare frames get a synthetic Ethernet header
        so that every record really is Ethernet, rather than a quarter of the file being
        mis-dissected as it is today in Wireshark.
      * The per-layer duplicates are dropped. Beyond the wasted space, a TCP reassembler
        reads the same segment arriving several times as heavy retransmission, which is
        enough to defeat stream reassembly and so the decryption that depends on it.

    Streams frame by frame, so memory does not grow with the capture, and reads the whole
    capture by default: this output is what the decrypter reads, so a packet cap would
    silently drop the later streams from it.

    @return: dict of counts, and the path written.
    """
    stats = {"path": "", "written": 0, "duplicates": 0, "wrapped": 0, "skipped": 0}
    warnings = []
    stats["warnings"] = warnings

    seen = set()
    try:
        with open(outPath, "wb") as handle:
            handle.write(_ClassicPcapHeader())
            for timestamp, frame in IterCapture(pcapPath, warnings, maxPackets):
                offset, ethertype = FrameOffsets(frame)
                if offset is None:
                    stats["skipped"] += 1
                    continue

                identity = hash(frame[offset:])
                if identity in seen:
                    stats["duplicates"] += 1
                    continue
                seen.add(identity)

                if offset == 0:
                    # Captured above the link layer, so give it the header its link type
                    # promises. ARP never appears without an Ethernet header.
                    frame = (
                        _SYNTHETIC_ETHERNET + struct.pack(">H", ethertype) + frame
                    )
                    stats["wrapped"] += 1

                seconds = int(timestamp)
                micros = int(round((timestamp - seconds) * 1000000))
                # Rounding can carry into the next second; libpcap readers reject usec >= 1e6.
                if micros >= 1000000:
                    seconds += 1
                    micros -= 1000000
                handle.write(
                    struct.pack("<IIII", seconds, micros, len(frame), len(frame))
                )
                handle.write(frame)
                stats["written"] += 1
    except OSError as e:
        log.warning("Could not write normalised capture to %s: %s", outPath, e)
        return stats

    if not stats["written"]:
        # Only a global header was written, which is not a capture. Leaving the path unset
        # keeps the caller's "could not convert" path, and the stub would never be reused
        # anyway since it is no larger than the header.
        with suppress(OSError):
            Path(outPath).unlink()
        return stats

    stats["path"] = str(outPath)
    return stats


def IsPcapng(pcapPath):
    """Whether a file starts with a pcapng section header block."""
    try:
        with open(pcapPath, "rb") as handle:
            return handle.read(4) == b"\x0a\x0d\x0d\x0a"
    except OSError:
        return False


def ParseClassicPcap(data, maxPackets=MAX_PACKETS):
    """Walk a classic libpcap buffer into (timestamp, frame) tuples.

    Needed because the file dialog accepts .pcap as well as .pcapng, and every capture that
    did not come from pktmon is likely to be this format. Without it a classic pcap parsed
    as zero packets, so the metadata view was empty while decryption - which reads this
    format natively - still worked, for no visible reason.
    """
    warnings = []
    return list(_IterClassicBuffer(data, warnings, maxPackets)), warnings


def ParseCapture(pcapPath, maxPackets=MAX_PACKETS):
    """Read either capture format into a list of (timestamp, frame) tuples."""
    warnings = []
    return list(IterCapture(pcapPath, warnings, maxPackets)), warnings


def _ValidIpv4(frame, offset):
    """Whether a self-consistent IPv4 header starts at *offset*."""
    if offset + 20 > len(frame):
        return False

    first = frame[offset]
    if first >> 4 != 4:
        return False

    headerLength = (first & 0x0F) * 4
    if headerLength < 20:
        return False

    totalLength = struct.unpack_from(">H", frame, offset + 2)[0]

    # A zero total length is not corruption: with checksum offload or large send offload the
    # NIC fills the length and checksum in, so a frame captured on the way down the stack
    # carries zero in both. Rejecting those loses real traffic - in a Hyper-V guest capture
    # it is every outbound segment on an offloaded connection.
    if totalLength == 0:
        return True

    # Not compared against the captured length: a truncated frame is shorter than the length
    # its header declares, and is still a valid header.
    return totalLength >= headerLength


def FrameOffsets(frame):
    """Locate the network layer in a frame, returning (offset, ethertype).

    pktmon captures the same traffic at several points in the stack and writes them into
    one file: frames taken at the miniport carry an Ethernet header, while those taken
    higher up are raw IP. The interface description block declares Ethernet for all of
    them, so the layer has to be recognised per frame rather than trusted from the header -
    otherwise every raw IP frame is read as Ethernet and silently mis-decoded.
    """
    if len(frame) >= 14:
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        if ethertype == ETH_VLAN and len(frame) >= 18:
            ethertype = struct.unpack_from(">H", frame, 16)[0]
            offset = 18

        if ethertype == ETH_IPV4 and _ValidIpv4(frame, offset):
            return offset, ETH_IPV4
        if ethertype in (ETH_IPV6, ETH_ARP):
            return offset, ethertype

    # No usable Ethernet header, so try the frame as bare IP.
    if _ValidIpv4(frame, 0):
        return 0, ETH_IPV4
    if frame and frame[0] >> 4 == 6 and len(frame) >= 40:
        return 0, ETH_IPV6

    return None, None


def ParseFrame(frame):
    """Decode one frame down to its transport payload.

    @return: dict, or None when the frame is not IP.
    """
    offset, ethertype = FrameOffsets(frame)
    if offset is None or ethertype == ETH_ARP:
        return None

    if ethertype == ETH_IPV4:
        headerLength = (frame[offset] & 0x0F) * 4
        protocol = frame[offset + 9]
        src = ".".join(str(b) for b in frame[offset + 12 : offset + 16])
        dst = ".".join(str(b) for b in frame[offset + 16 : offset + 20])
        transport = offset + headerLength
    else:
        if offset + 40 > len(frame):
            return None
        protocol = frame[offset + 6]
        src = _Ipv6Text(frame[offset + 8 : offset + 24])
        dst = _Ipv6Text(frame[offset + 24 : offset + 40])
        transport = offset + 40

    packet = {
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "sport": 0,
        "dport": 0,
        "payload": b"",
        "flags": 0,
        # Where the network layer began, so a caller can identify a frame by its IP bytes
        # alone and recognise the same packet captured at another layer.
        "ip_offset": offset,
    }

    if protocol == IP_TCP and transport + 20 <= len(frame):
        packet["sport"], packet["dport"] = struct.unpack_from(">HH", frame, transport)
        dataOffset = ((frame[transport + 12] >> 4) & 0x0F) * 4
        packet["flags"] = frame[transport + 13]
        packet["payload"] = frame[transport + max(dataOffset, 20) :]
    elif protocol == IP_UDP and transport + 8 <= len(frame):
        packet["sport"], packet["dport"] = struct.unpack_from(">HH", frame, transport)
        packet["payload"] = frame[transport + 8 :]
    else:
        return None

    return packet


def _Ipv6Text(raw):
    groups = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


def ParseDns(payload):
    """Summarise a DNS message with dnspython, which is already a project dependency."""
    import dns.message

    try:
        message = dns.message.from_wire(payload)
    except Exception:
        return None

    queries = [question.name.to_text(omit_final_dot=True) for question in message.question]
    answers = []
    for rrset in message.answer:
        for item in rrset:
            answers.append(
                {
                    "name": rrset.name.to_text(omit_final_dot=True),
                    "type": dns.rdatatype.to_text(rrset.rdtype),
                    "data": item.to_text(),
                }
            )

    isResponse = bool(message.flags & 0x8000)
    return {
        "queries": queries,
        "answers": answers,
        "response": isResponse,
        "rcode": message.rcode().name if isResponse else "",
        "text": message.to_text(),
    }


HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)


def ParseHttp(payload):
    """Pull the start line and headers out of a cleartext HTTP message.

    Only the segment that carries the start line is recognised: reassembling a stream to
    follow a body across segments is well beyond what this view needs.
    """
    if not payload.startswith(HTTP_METHODS) and not payload.startswith(b"HTTP/"):
        return None

    head, _, _ = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return None

    startLine = lines[0].decode("utf-8", "replace")
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers[name.decode("utf-8", "replace").strip()] = value.decode(
                "utf-8", "replace"
            ).strip()

    return {
        "start_line": startLine,
        "headers": headers,
        "response": payload.startswith(b"HTTP/"),
    }


TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def ParseTlsHandshake(payload):
    """Read a ClientHello or ServerHello out of a TLS record.

    The client random is the point of this: it is what joins a session in the capture to a
    secret in the key log, so the view can say which sessions are decryptable.

    A hello is very often cut short - pktmon truncates each frame to a fixed capture size,
    so a 181 byte hello can arrive as 74 bytes. The random sits at a fixed offset near the
    front and survives that, while the extensions carrying SNI do not, so a truncated hello
    is reported with whatever was captured rather than discarded. Returning None here would
    throw away the only field that matters for matching secrets.
    """
    # 43 bytes gets us through the client random; without it there is nothing to match on.
    if len(payload) < 43 or payload[0] != 0x16:
        return None

    recordVersion = struct.unpack_from(">H", payload, 1)[0]
    if recordVersion not in TLS_VERSIONS:
        return None

    handshakeType = payload[5]
    if handshakeType not in (0x01, 0x02):
        return None

    # The record header declares the full handshake length, so comparing it against what
    # was captured is how truncation is detected.
    recordLength = struct.unpack_from(">H", payload, 3)[0]
    truncated = recordLength + 5 > len(payload)

    # handshake: type(1) length(3), then the hello body
    helloVersion = struct.unpack_from(">H", payload, 9)[0]
    # The random sits at the same offset in both hellos but belongs to whichever side sent
    # it, so it must not be recorded under one name for both. Storing a ServerHello's random
    # as the client random made every ServerHello miss the key log (a server random is
    # matched against client randoms and never hits), and it loses the server random that a
    # (client_random, server_random) keyed master-secret lookup needs.
    isClientHello = handshakeType == 0x01
    random = payload[11:43].hex()

    parsed = {
        "hello": "ClientHello" if isClientHello else "ServerHello",
        "version": TLS_VERSIONS.get(helloVersion, f"0x{helloVersion:04x}"),
        "random": random,
        "client_random": random if isClientHello else "",
        "server_random": "" if isClientHello else random,
        "server_names": [],
        "truncated": truncated,
    }

    offset = 43
    sessionLength = payload[offset]
    offset += 1 + sessionLength

    if isClientHello:
        if offset + 2 > len(payload):
            return parsed
        suitesLength = struct.unpack_from(">H", payload, offset)[0]
        offset += 2 + suitesLength
        if offset >= len(payload):
            return parsed
        compressionLength = payload[offset]
        offset += 1 + compressionLength
    else:
        # ServerHello names a single suite and compression method.
        offset += 3

    if offset + 2 <= len(payload):
        extensionsLength = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        end = min(offset + extensionsLength, len(payload))
        parsed["server_names"] = _ServerNames(payload, offset, end)

    return parsed


def _ServerNames(payload, offset, end):
    """Extract SNI host names from a hello's extension list."""
    names = []
    while offset + 4 <= end:
        extensionType, extensionLength = struct.unpack_from(">HH", payload, offset)
        offset += 4
        if extensionType == 0 and offset + 2 <= end:
            # server_name_list: length(2), then entries of type(1) length(2) name
            listEnd = min(offset + extensionLength, end)
            cursor = offset + 2
            while cursor + 3 <= listEnd:
                nameType = payload[cursor]
                nameLength = struct.unpack_from(">H", payload, cursor + 1)[0]
                cursor += 3
                if nameType == 0:
                    names.append(
                        payload[cursor : cursor + nameLength].decode("utf-8", "replace")
                    )
                cursor += nameLength

        offset += extensionLength

    return names


def _FormatDetail(pairs, body=""):
    """A label/value block for the detail pane, with an optional raw section beneath."""
    width = max((len(label) for label, _ in pairs), default=0)
    lines = [f"{label + ':':<{width + 2}}{value}" for label, value in pairs]
    if body:
        lines.append("")
        lines.append(body)

    return "\n".join(lines)


def _Host(hosts, ip):
    """An address with the name it resolved from, when one is known."""
    names = hosts.get(ip)
    if not names:
        return ip

    return f"{ip} ({sorted(names)[0]})"


def _DnsEvent(packet, payload, hosts):
    parsed = ParseDns(payload)
    if parsed is None:
        return None

    for answer in parsed["answers"]:
        if answer["type"] in ("A", "AAAA"):
            hosts.setdefault(answer["data"], set()).add(answer["name"])

    query = parsed["queries"][0] if parsed["queries"] else "?"
    if parsed["response"]:
        addresses = [a["data"] for a in parsed["answers"] if a["type"] in ("A", "AAAA")]
        summary = ", ".join(addresses) if addresses else parsed["rcode"]
        info = f"response {query} -> {summary}"
    else:
        info = f"query {query}"

    detail = _FormatDetail(
        [
            ("Type", "response" if parsed["response"] else "query"),
            ("Source", packet["src"]),
            ("Destination", packet["dst"]),
            ("Question", ", ".join(parsed["queries"]) or "none"),
            ("Rcode", parsed["rcode"] or "-"),
        ],
        parsed["text"],
    )

    return {
        "kind": "DNS",
        "collapse": ("DNS", info),
        "src": packet["src"],
        "dst": packet["dst"],
        "host": query,
        "info": info,
        "keys": "",
        "detail": detail,
    }


def _HttpEvent(packet, payload):
    parsed = ParseHttp(payload)
    if parsed is None:
        return None

    host = parsed["headers"].get("Host", "")
    info = parsed["start_line"]
    if host and not parsed["response"]:
        info = f"{info}  [{host}]"

    headerLines = "\n".join(
        f"    {name}: {value}" for name, value in parsed["headers"].items()
    )
    detail = _FormatDetail(
        [
            ("Source", f'{packet["src"]}:{packet["sport"]}'),
            ("Destination", f'{packet["dst"]}:{packet["dport"]}'),
            ("Start line", parsed["start_line"]),
        ],
        f"Headers:\n{headerLines}" if headerLines else "",
    )

    return {
        "kind": "HTTP",
        "collapse": ("HTTP", packet["dst"], packet["dport"], info),
        "src": packet["src"],
        "dst": packet["dst"],
        "host": host,
        "info": info,
        "keys": "",
        "detail": detail,
    }


def _TlsEvent(packet, payload, keylog, hosts, sessions):
    parsed = ParseTlsHandshake(payload)
    if parsed is None:
        return None

    names = parsed["server_names"]
    host = names[0] if names else ""
    if host:
        hosts.setdefault(packet["dst"], set()).add(host)

    # Only a ClientHello carries the random the key log is indexed by; a ServerHello's random
    # would never match, so it is reported as unknown rather than as a miss.
    isClientHello = bool(parsed["client_random"])
    hasKeys = isClientHello and parsed["client_random"] in keylog["client_randoms"]
    if isClientHello:
        # By random rather than by hello: the same hello is captured at several layers and
        # retransmitted, so counting occurrences reported nine sessions where there were three.
        sessions["randoms"].add(parsed["client_random"])
        if hasKeys:
            sessions["with_keys"].add(parsed["client_random"])

    info = f'{parsed["hello"]} {parsed["version"]}'
    if host:
        info = f"{info}  {host}"
    elif parsed["truncated"]:
        info = f"{info}  (frame truncated before SNI)"

    if names:
        serverName = ", ".join(names)
    elif parsed["truncated"]:
        serverName = "not captured - the frame was truncated before the extensions"
    else:
        serverName = "none offered"

    if isClientHello:
        randomLabel = "Client random"
        secrets = (
            "present in the merged key log"
            if hasKeys
            else "not in the key log, this session cannot be decrypted"
        )
    else:
        randomLabel = "Server random"
        secrets = "matched on the ClientHello of this session, not here"

    detail = _FormatDetail(
        [
            ("Message", parsed["hello"]),
            ("Version", parsed["version"]),
            ("Source", f'{packet["src"]}:{packet["sport"]}'),
            ("Destination", f'{packet["dst"]}:{packet["dport"]}'),
            ("Server name", serverName),
            (randomLabel, parsed["random"]),
            ("Secrets", secrets),
        ]
    )

    return {
        "kind": "TLS",
        "collapse": ("TLS", parsed["hello"], parsed["random"]),
        "src": packet["src"],
        "dst": packet["dst"],
        "host": host,
        "info": info,
        "keys": ("yes" if hasKeys else "no") if isClientHello else "",
        "detail": detail,
    }


def _FlowRows(flows, hosts):
    """Collapse the per-packet counters into one row per conversation."""
    rows = []
    for key in sorted(flows, key=lambda k: flows[k]["bytes"], reverse=True):
        src, sport, dst, dport, protocol = key
        stats = flows[key]
        if protocol == IP_TCP:
            name = "TCP"
        elif protocol == IP_UDP:
            name = "UDP"
        else:
            name = str(protocol)

        rows.append(
            {
                "kind": "Flow",
                "time": stats["first"],
                "src": f"{src}:{sport}",
                "dst": f"{dst}:{dport}",
                "host": sorted(hosts.get(dst, [""]))[0],
                "info": (
                    f'{name}, {stats["packets"]} packet(s), '
                    f'{stats["bytes"]} payload byte(s)'
                ),
                "keys": "",
                "detail": _FormatDetail(
                    [
                        ("Protocol", name),
                        ("Source", f"{src}:{sport}"),
                        ("Destination", f"{_Host(hosts, dst)}:{dport}"),
                        ("Packets", stats["packets"]),
                        ("Payload bytes", stats["bytes"]),
                        ("First seen", FormatTime(stats["first"])),
                    ]
                ),
            }
        )

    return rows


def _CollapseEvents(events):
    """One row per distinct observation, carrying how many times it was seen.

    The same question really is asked several times over - a resolver is queried on more
    than one interface, and a request that gets no answer is retried - so these are not
    capture artefacts to be discarded like the per-layer duplicates. Collapsing them keeps
    the count while getting four identical rows down to one.
    """
    collapsed = {}
    for event in events:
        # Each producer names its own identity. Collapsing on the summary text alone folded
        # nine separate TLS sessions into one row, because a hello truncated before its SNI
        # summarises identically no matter which server it was for.
        key = event.pop("collapse")
        first = collapsed.get(key)
        if first is None:
            event["repeats"] = 1
            collapsed[key] = event
            continue

        first["repeats"] += 1
        first["last"] = event["time"]

    rows = list(collapsed.values())
    for row in rows:
        if row["repeats"] > 1:
            last = FormatTime(row.get("last", row["time"]))
            row["detail"] += f'\n\nSeen {row["repeats"]} times, last at {last}.'

    return rows


def NetworkData(analysisDir, pcapPath, maxPackets=MAX_PACKETS):
    """Correlate a user-supplied capture with the TLS secrets from the analysis.

    @return: dict of events, flows, host names and key log details for the Network tab.
    """
    keylog = BuildKeyLog(analysisDir)
    packets, warnings = ParseCapture(pcapPath, maxPackets)

    events = []
    flows = {}
    hosts = {}
    seen = set()
    counts = Counter()
    sessions = {"randoms": set(), "with_keys": set()}

    for timestamp, frame in packets:
        counts["frames"] += 1
        packet = ParseFrame(frame)
        if packet is None:
            counts["not_ip"] += 1
            continue

        # pktmon writes the same packet once per stack layer it traversed, so without this
        # every event shows up several times over and every byte is counted more than once.
        identity = hash(frame[packet["ip_offset"] :])
        if identity in seen:
            counts["duplicates"] += 1
            continue

        seen.add(identity)
        counts["packets"] += 1

        key = (
            packet["src"],
            packet["sport"],
            packet["dst"],
            packet["dport"],
            packet["protocol"],
        )
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = {"packets": 0, "bytes": 0, "first": timestamp}
        flow["packets"] += 1
        flow["bytes"] += len(packet["payload"])

        payload = packet["payload"]
        if not payload:
            continue

        event = None
        if packet["protocol"] == IP_UDP and 53 in (packet["sport"], packet["dport"]):
            event = _DnsEvent(packet, payload, hosts)
        elif packet["protocol"] == IP_TCP:
            event = _HttpEvent(packet, payload)
            if event is None:
                event = _TlsEvent(packet, payload, keylog, hosts, sessions)

        if event is None:
            continue

        event["time"] = timestamp
        counts[event["kind"]] += 1
        events.append(event)

    return {
        "pcap": str(pcapPath),
        "keylog": keylog,
        "events": _CollapseEvents(events),
        "flows": _FlowRows(flows, hosts),
        "hosts": {ip: sorted(names) for ip, names in hosts.items()},
        "counts": dict(counts),
        "sessions": {
            "total": len(sessions["randoms"]),
            "with_keys": len(sessions["with_keys"]),
        },
        "warnings": warnings,
    }
