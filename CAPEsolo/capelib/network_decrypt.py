"""Decrypt TLS streams in a capture using the secrets captured during analysis.

This is CAPEv2's approach, from modules/processing/network.py (the Pcap2 class and
get_tlsmaster): hand httpreplay a mapping of TLS randoms to master secrets and let it
reassemble and decrypt the streams, producing the plaintext requests and responses.

The engine is httpreplay-ng, which imports as "httpreplay" and is on PyPI, so it installs
as an ordinary dependency. Kept apart from network.py all the same: network.py stays
importable - and the Network tab's summary keeps working - on an install where dpkt or
httpreplay are missing or broken.

Both secret sources feed it. capemon's tlsdump.log carries the client random, the server
random and the master secret together, which is the pair CAPEv2 keys on. httpreplay also
accepts the NSS CLIENT_RANDOM form on its own (see its read_tlsmaster), so the secrets the
sslkeylogfile module collects are usable here too - which CAPEv2's get_tlsmaster does not
do. TLS 1.3 traffic secrets are excluded: they are not master secrets.
"""

import binascii
import hashlib
import logging
import os
import re
from pathlib import Path

from .network import BuildKeyLog, IsPcapng, NormalisePcap
from .path_utils import path_exists, path_mkdir

log = logging.getLogger(__name__)

# Same expression CAPEv2 uses, so a tlsdump line either module accepts is accepted by both.
TLS12_LINE = re.compile(
    r"client_random:\s*(?P<client_random>[a-f0-9]+)\s*,\s*"
    r"server_random:\s*(?P<server_random>[a-f0-9]+)\s*,\s*"
    r"master_secret:\s*(?P<master_secret>[a-f0-9]+)",
    re.I,
)

TLSDUMP_LOG = "tlsdump/tlsdump.log"

# Ports httpreplay is told how to interpret. Mirrors CAPEv2's handler map.
HTTP_PORTS = (80, 8000, 8080)
HTTPS_PORTS = (443, 4443, 8443)
SMTP_PORTS = (25, 465)
SMTP_TLS_PORTS = (587,)

# Bodies are written out by hash, so a response can be inspected or scanned like any other
# dropped file rather than only read in the report.
BODY_DIR = "network"

# A classic pcap global header alone is 24 bytes, so a file no larger than that holds no
# packets and has to be rebuilt whatever its timestamp says.
PCAP_HEADER_SIZE = 24


def _ConvertedPath(networkDir, pcapPath):
    """Where the classic-pcap rewrite of *pcapPath* lives.

    Named after the source, and tagged with a hash of its full path, so that processing a
    second capture into the same analysis folder cannot read the first one's rewrite - which
    a single fixed name would do silently.
    """
    source = Path(pcapPath)
    tag = hashlib.sha1(str(source.resolve()).lower().encode()).hexdigest()[:8]
    return os.path.join(networkDir, f"{source.stem}_{tag}_normalised.pcap")


def _IsFresh(derived, source):
    """Whether an existing rewrite can be reused instead of rebuilt."""
    try:
        derivedStat = os.stat(derived)
        sourceStat = os.stat(source)
    except OSError:
        return False

    return (
        derivedStat.st_size > PCAP_HEADER_SIZE
        and derivedStat.st_mtime >= sourceStat.st_mtime
    )


INSTALL_HINT = "pip install httpreplay-ng"


def Unavailable():
    """Why decryption cannot run, or "" when it can.

    Checked at call time rather than by a module-level import so a missing or wrong
    httpreplay degrades to "no decryption" instead of breaking the whole report.

    The wrong one still has to be detected, not just a missing one: httpreplay-ng imports as
    "httpreplay", and PyPI also carries the older project of that literal name, the one it was
    forked from. Install that by mistake and the modules import perfectly and then cannot
    decrypt. Capabilities are probed rather than a version string, since capability is what
    actually has to hold and the two projects version independently.
    """
    try:
        import dpkt  # noqa: F401
    except Exception as e:
        return f"dpkt is not installed ({e})"

    try:
        import httpreplay.cut
        import httpreplay.misc
        import httpreplay.reader
        import httpreplay.smegma
    except Exception as e:
        return f"httpreplay-ng is not installed ({e}); {INSTALL_HINT}"

    required = (
        (httpreplay.cut, "https_handler"),
        (httpreplay.cut, "smtp_handler"),
        (httpreplay.reader, "PcapReader"),
        (httpreplay.smegma, "TCPPacketStreamer"),
        # Fork additions. Their absence means the PyPI project got installed instead.
        (httpreplay.misc, "read_tlsmaster"),
        (httpreplay.misc, "JA3"),
    )
    missing = [
        f"{module.__name__}.{name}"
        for module, name in required
        if not hasattr(module, name)
    ]
    if missing:
        return (
            "the installed httpreplay is not httpreplay-ng - missing "
            + ", ".join(missing)
            + f". Replace it with: {INSTALL_HINT}"
        )

    return ""


def Available():
    """Whether TLS stream decryption can run."""
    reason = Unavailable()
    if reason:
        log.debug("TLS decryption unavailable: %s", reason)

    return not reason


def GetTlsMaster(analysisDir):
    """Collect every TLS master secret the analysis captured, in httpreplay's key forms.

    httpreplay accepts two keyings, and this returns both in one dict because its own
    read_tlsmaster does the same:

      * (client_random, server_random) -> master_secret, from capemon's tlsdump records,
        which are the only source carrying both randoms;
      * client_random -> master_secret, the NSS CLIENT_RANDOM form, which is what the
        sslkeylogfile module collects and what capemon's TLS 1.2 records convert to.

    Reading the NSS side as well is what lets an SSLKEYLOGFILE-honouring application be
    decrypted at all; CAPEv2's get_tlsmaster reads only the capemon pairs.

    TLS 1.3 traffic secrets are deliberately excluded. They are not master secrets, so
    handing them over as though they were would key sessions with the wrong material.
    """
    tlsmaster = {}
    source = Path(analysisDir) / TLSDUMP_LOG
    if path_exists(str(source)):
        try:
            raw = source.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Could not read TLS secrets from %s: %s", source, e)
            raw = ""

        for line in raw.splitlines():
            match = TLS12_LINE.search(line)
            if not match:
                continue

            try:
                clientRandom = binascii.a2b_hex(match.group("client_random"))
                serverRandom = binascii.a2b_hex(match.group("server_random"))
                masterSecret = binascii.a2b_hex(match.group("master_secret"))
            except (binascii.Error, ValueError) as e:
                log.warning("Malformed tlsdump record skipped: %s", e)
                continue

            # An all-zero secret is a record written before the key was available.
            if not masterSecret.strip(b"\x00"):
                continue

            tlsmaster[clientRandom, serverRandom] = masterSecret
            # Also under the client random alone, so a session whose server random was never
            # observed still resolves.
            tlsmaster.setdefault(clientRandom, masterSecret)

    # BuildKeyLog already normalises both secret files into NSS lines, including converting
    # capemon's TLS 1.2 form, so reuse it rather than parsing the same files again.
    try:
        merged = BuildKeyLog(analysisDir, write=False)
    except Exception as e:
        log.warning("Could not merge the TLS key log: %s", e)
        return tlsmaster

    for entry in merged.get("lines") or ():
        fields = entry.split()
        if len(fields) != 3 or fields[0] != "CLIENT_RANDOM":
            continue

        try:
            clientRandom = binascii.a2b_hex(fields[1])
            masterSecret = binascii.a2b_hex(fields[2])
        except (binascii.Error, ValueError):
            continue

        tlsmaster.setdefault(clientRandom, masterSecret)

    return tlsmaster


def _Handlers(tlsmaster):
    """Port to protocol handler map, as CAPEv2 builds it."""
    import httpreplay.cut

    handlers = {}
    for port in HTTP_PORTS:
        handlers[port] = httpreplay.cut.http_handler
    for port in HTTPS_PORTS:
        handlers[port] = lambda: httpreplay.cut.https_handler(tlsmaster)
    for port in SMTP_PORTS:
        handlers[port] = httpreplay.cut.smtp_handler
    for port in SMTP_TLS_PORTS:
        handlers[port] = lambda: httpreplay.cut.smtp_handler(tlsmaster)

    return handlers


def _WriteBody(networkDir, body):
    """Store a request or response body by sha256 and return its digests."""
    digests = {
        "md5": hashlib.md5(body).hexdigest(),
        "sha1": hashlib.sha1(body).hexdigest(),
        "sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
    }
    try:
        if not path_exists(networkDir):
            path_mkdir(networkDir, exist_ok=True)
        target = os.path.join(networkDir, digests["sha256"])
        if not path_exists(target):
            Path(target).write_bytes(body)
        digests["path"] = target
    except OSError as e:
        log.warning("Could not write network body: %s", e)

    return digests


def DecryptStreams(analysisDir, pcapPath, tlsmaster=None):
    """Reassemble and decrypt the streams in *pcapPath*.

    @return: dict with http_ex, https_ex and smtp_ex lists plus a status summary. The keys
             match CAPEv2's so the same report and signature code can read either.
    """
    output = {
        "http_ex": [],
        "https_ex": [],
        "smtp_ex": [],
        "available": False,
        "secrets": 0,
        "error": "",
        "converted": {},
    }

    reason = Unavailable()
    if reason:
        # Carries the specific reason, so the Network tab can say what to install rather than
        # only that decryption did not happen.
        output["error"] = f"cannot decrypt streams: {reason}"
        return output

    output["available"] = True
    if tlsmaster is None:
        tlsmaster = GetTlsMaster(analysisDir)
    output["secrets"] = len(tlsmaster)

    if not path_exists(str(pcapPath)):
        output["error"] = f"capture not found: {pcapPath}"
        return output

    import httpreplay.reader
    import httpreplay.smegma

    networkDir = os.path.join(analysisDir, BODY_DIR)

    # httpreplay reads classic pcap only, and a pktmon capture is always pcapng with mixed
    # link layers and per-layer duplicates. NormalisePcap resolves all three; without it this
    # returns nothing at all on the captures CAPEsolo is actually given.
    readPath = pcapPath
    if IsPcapng(pcapPath):
        converted = _ConvertedPath(networkDir, pcapPath)
        if not path_exists(networkDir):
            try:
                path_mkdir(networkDir, exist_ok=True)
            except OSError as e:
                output["error"] = f"could not create {networkDir}: {e}"
                return output

        if _IsFresh(converted, pcapPath):
            # The rewrite is a full parse of the capture and this runs again for every report
            # generated from the same analysis, so an unchanged capture is converted once.
            output["converted"] = {"path": converted, "reused": True}
            log.debug("Reusing the existing rewrite at %s", converted)
        else:
            stats = NormalisePcap(pcapPath, converted)
            output["converted"] = stats
            if not stats.get("path"):
                output["error"] = "could not convert the pcapng for decryption"
                return output

            log.info(
                "Normalised %s: %d frames written, %d duplicates dropped, %d given a link header",
                pcapPath,
                stats["written"],
                stats["duplicates"],
                stats["wrapped"],
            )

        readPath = converted

    try:
        with open(readPath, "rb") as handle:
            reader = httpreplay.reader.PcapReader(handle)
            reader.tcp = httpreplay.smegma.TCPPacketStreamer(reader, _Handlers(tlsmaster))
            # Sorted by timestamp so the report reads in the order things happened; the
            # generator yields per completed stream, not per packet.
            streams = sorted(reader.process(), key=lambda item: item[1])
    except Exception as e:
        # httpreplay raises a wide variety of parse errors on real-world captures, and a
        # failure here must not take the rest of the report down with it.
        log.warning("httpreplay could not process %s: %s", readPath, e)
        output["error"] = f"httpreplay failed: {e}"
        return output

    for tup, timestamp, protocol, sent, recv in streams:
        srcip, srcport, dstip, dstport = tup
        try:
            if protocol == "smtp":
                output["smtp_ex"].append(
                    _SmtpEntry(srcip, srcport, dstip, dstport, protocol, timestamp, sent, recv)
                )
            elif protocol in ("http", "https"):
                output[f"{protocol}_ex"].append(
                    _HttpEntry(
                        srcip, srcport, dstip, dstport, protocol, timestamp, sent, recv, networkDir
                    )
                )
        except Exception as e:
            log.debug("Skipping malformed %s stream: %s", protocol, e)

    return output


def _SmtpEntry(srcip, srcport, dstip, dstport, protocol, timestamp, sent, recv):
    return {
        "src": srcip,
        "sport": srcport,
        "dst": dstip,
        "dport": dstport,
        "protocol": protocol,
        "first_seen": timestamp,
        "req": {
            "hostname": getattr(sent, "hostname", ""),
            "mail_from": getattr(sent, "mail_from", ""),
            "mail_to": getattr(sent, "mail_to", ""),
            "auth_type": getattr(sent, "auth_type", ""),
            "username": getattr(sent, "username", ""),
            "headers": getattr(sent, "headers", {}),
            "mail_body": getattr(sent, "message", ""),
        },
        "resp": {"banner": getattr(recv, "ready_message", "")},
    }


def _HttpEntry(srcip, srcport, dstip, dstport, protocol, timestamp, sent, recv, networkDir):
    """One decrypted request/response pair, in CAPEv2's http_ex/https_ex shape."""
    request = b""
    response = b""
    if isinstance(getattr(sent, "raw", None), bytes):
        request = sent.raw.split(b"\r\n\r\n", 1)[0]
    if isinstance(getattr(recv, "raw", None), bytes):
        response = recv.raw.split(b"\r\n\r\n", 1)[0]

    try:
        status = int(getattr(recv, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0

    headers = getattr(sent, "headers", {}) or {}
    entry = {
        "src": srcip,
        "sport": srcport,
        "dst": dstip,
        "dport": dstport,
        "protocol": protocol,
        "method": getattr(sent, "method", ""),
        "host": headers.get("host", dstip),
        "uri": getattr(sent, "uri", ""),
        "status": status,
        # latin-1 never fails and keeps every byte recoverable, which utf-8 with
        # replacement would not.
        "request": request.decode("latin-1"),
        "response": response.decode("latin-1"),
        "first_seen": timestamp,
    }

    # Redirects carry no body worth storing, matching CAPEv2's filter.
    if status and status not in (301, 302):
        body = getattr(sent, "body", None)
        if body:
            entry["req"] = _WriteBody(networkDir, body)
        body = getattr(recv, "body", None)
        if body:
            digests = _WriteBody(networkDir, body)
            digests["preview"] = _Preview(body)
            entry["resp"] = digests

    return entry


# Requests and responses are shown in full, but a body-bearing response can be hundreds of
# kilobytes and the native text control redraws the whole value on every selection.
MAX_BLOCK_CHARS = 8000


def _Block(title, text):
    """One labelled section of the detail pane, truncated if very large."""
    if not text:
        return ""

    if len(text) > MAX_BLOCK_CHARS:
        text = (
            text[:MAX_BLOCK_CHARS]
            + f"\n... [truncated, {len(text)} chars total; the full body is on disk] ..."
        )

    return f"--- {title} ---\n{text}"


def _BodyBlock(title, digests):
    """Describe a stored body: where it went, and what its first bytes look like."""
    if not digests:
        return ""

    lines = [
        f"--- {title} ---",
        f'sha256 {digests.get("sha256", "")}  ({digests.get("size", 0)} bytes)',
    ]
    if digests.get("path"):
        lines.append(f'saved to {digests["path"]}')
    for line in digests.get("preview") or ():
        lines.append(line)

    return "\n".join(lines)


def StreamRows(decrypted, formatTime=None):
    """Turn decrypted streams into display rows shaped like capelib.network's events.

    Returned here rather than in the panel so the Network tab concatenates one list of rows
    from both halves of the pipeline instead of knowing two record layouts.
    """
    if not decrypted:
        return []

    if formatTime is None:
        formatTime = lambda value: f"{value:.6f}" if value else ""

    rows = []
    for key in ("http_ex", "https_ex", "smtp_ex"):
        for entry in decrypted.get(key) or ():
            if key == "smtp_ex":
                rows.append(_SmtpRow(entry, formatTime))
            else:
                rows.append(_HttpRow(entry, formatTime, encrypted=key == "https_ex"))

    return rows


def _HttpRow(entry, formatTime, encrypted):
    protocol = entry.get("protocol") or ("https" if encrypted else "http")
    host = entry.get("host") or entry.get("dst") or ""
    uri = entry.get("uri") or "/"
    status = entry.get("status") or 0
    source = f'{entry.get("src", "")}:{entry.get("sport", "")}'
    destination = f'{entry.get("dst", "")}:{entry.get("dport", "")}'

    info = f'{protocol} {entry.get("method", "")} {host}{uri}'
    if status:
        info = f"{info} -> {status}"

    header = [
        ("Protocol", f"{protocol} (decrypted)" if encrypted else protocol),
        ("Method", entry.get("method", "")),
        ("Host", host),
        ("URI", uri),
        ("Status", status or "no response"),
        ("Source", source),
        ("Destination", destination),
        ("First seen", formatTime(entry.get("first_seen") or 0.0)),
    ]
    width = max(len(label) for label, _ in header)
    sections = ["\n".join(f"{label + ':':<{width + 2}}{value}" for label, value in header)]

    for block in (
        _Block("request", entry.get("request") or ""),
        _Block("response", entry.get("response") or ""),
        _BodyBlock("request body", entry.get("req")),
        _BodyBlock("response body", entry.get("resp")),
    ):
        if block:
            sections.append(block)

    return {
        "kind": "Plaintext",
        "time": entry.get("first_seen") or 0.0,
        "src": source,
        "dst": destination,
        "host": host,
        "info": info,
        # The stream was only readable because a secret matched, so say so in the column that
        # answers that question for the handshake rows.
        "keys": "yes" if encrypted else "",
        "repeats": 1,
        "detail": "\n\n".join(sections),
    }


def _SmtpRow(entry, formatTime):
    request = entry.get("req") or {}
    mailTo = request.get("mail_to") or ""
    if isinstance(mailTo, (list, tuple)):
        mailTo = ", ".join(str(item) for item in mailTo)

    source = f'{entry.get("src", "")}:{entry.get("sport", "")}'
    destination = f'{entry.get("dst", "")}:{entry.get("dport", "")}'
    info = f'smtp {request.get("mail_from", "") or "?"} -> {mailTo or "?"}'

    header = [
        ("Protocol", "smtp"),
        ("Hostname", request.get("hostname", "")),
        ("Mail from", request.get("mail_from", "")),
        ("Mail to", mailTo),
        ("Auth", request.get("auth_type", "")),
        ("Username", request.get("username", "")),
        ("Source", source),
        ("Destination", destination),
        ("First seen", formatTime(entry.get("first_seen") or 0.0)),
    ]
    width = max(len(label) for label, _ in header)
    sections = ["\n".join(f"{label + ':':<{width + 2}}{value}" for label, value in header)]

    headers = request.get("headers") or {}
    if headers:
        sections.append(
            "--- headers ---\n"
            + "\n".join(f"    {name}: {value}" for name, value in headers.items())
        )

    body = request.get("mail_body") or ""
    if isinstance(body, bytes):
        body = body.decode("latin-1")
    block = _Block("message", body)
    if block:
        sections.append(block)

    banner = (entry.get("resp") or {}).get("banner") or ""
    if banner:
        sections.append(f"--- server banner ---\n{banner}")

    return {
        "kind": "Plaintext",
        "time": entry.get("first_seen") or 0.0,
        "src": source,
        "dst": destination,
        "host": request.get("hostname", ""),
        "info": info,
        "keys": "",
        "repeats": 1,
        "detail": "\n\n".join(sections),
    }


def _Preview(body, rows=3):
    """A short hex/ascii preview of a body, so the report shows what it is at a glance."""
    lines = []
    for row in range(rows):
        chunk = body[row * 16 : row * 16 + 16]
        if not chunk:
            break

        hexPart = " ".join(f"{value:02x}" for value in chunk)
        # Extra space between the two groups of eight, as a hex dump is normally laid out.
        hexPart = f"{hexPart[:23]} {hexPart[23:]}"
        asciiPart = "".join(chr(v) if 32 <= v <= 127 else "." for v in chunk)
        lines.append(f"{row * 16:08x}  {hexPart:<48}  |{asciiPart}|")

    return lines
