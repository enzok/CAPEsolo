"""Assemble the JS interceptor's raw TCP events into readable network conversations.

The js_console interceptor logs socket-level traffic as ordered tcp_connect / tcp_endpoints /
tcp_send / tcp_receive / tcp_error events, each tagged with a per-socket conn_id, and streams large
or binary payloads to files/<sha256> (referenced from the event body, with the sha256 stamped on by
js_log.JsLog). This module groups those events per connection, reconstructs the sent and received
byte streams, decodes any HTTP messages riding on them, and - when a file was transferred - hands
back drop descriptors so the caller can register the file into the standard Payloads/YARA pipeline.

Kept out of the wx panel so the parsing is importable and unit-testable on its own.
"""

import hashlib
import json
import logging
import os

from .network import _FormatDetail
from .network_decrypt import _Block
from .path_utils import path_exists

log = logging.getLogger(__name__)

# Body views are bounded so a large transfer cannot flood a control or the report.
BODY_TEXT_CAP = 64 * 1024
HEX_PREVIEW = 512

# Content-Type values (plus any image/*) that mean "this body is a file", used alongside the
# binary-content heuristic to decide whether to drop a reconstructed body.
FILE_CONTENT_TYPES = (
    "application/octet-stream",
    "application/zip",
    "application/x-msdownload",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/pdf",
    "application/gzip",
    "application/x-gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
)


# -- HTTP stream parsing ----------------------------------------------------
def IsProbablyText(data):
    """Mirror of the interceptor's isProbablyText: a NUL or >10% control chars (allowing
    tab/newlines) means binary. Sampled to the first 4 KB so large bodies stay cheap."""
    sample = data[:4096]
    n = len(sample)
    if n == 0:
        return True
    suspicious = 0
    for c in sample:
        if c == 0:
            return False
        if c < 0x09 or (0x0D < c < 0x20):
            suspicious += 1
    return suspicious / n < 0.1


def HexPreview(data):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:08x}  {hexs:<47}  {ascii_}")
    return "\n".join(lines)


def DeChunk(body):
    """Reassemble a Transfer-Encoding: chunked body. Returns (reassembled bytes, bytes consumed) so a
    stream parser can advance past this message to the next one."""
    out = bytearray()
    i, n = 0, len(body)
    consumed = n
    while i < n:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        token = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            break
        if size == 0:
            end = body.find(b"\r\n\r\n", i)  # terminator plus any trailers, up to the final CRLF
            consumed = end + 4 if end >= 0 else n
            break
        start = j + 2
        out += body[start:start + size]
        i = start + size + 2
    return bytes(out), consumed


def Decompress(data, encoding):
    """Best-effort Content-Encoding decode; unknown/failed encodings return the bytes unchanged."""
    import gzip
    import zlib

    try:
        if "gzip" in encoding:
            return gzip.decompress(data)
        if "deflate" in encoding:
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
        if "br" in encoding:
            import brotli

            return brotli.decompress(data)
    except Exception:
        pass
    return data


def HeaderValue(lowerHead, name):
    """Value of a header from the lower-cased header block; name includes the trailing colon."""
    idx = lowerHead.find(name)
    if idx < 0:
        return ""
    return lowerHead[idx + len(name):].split("\r\n", 1)[0].strip()


def SplitHttpMessages(raw):
    """Walk a raw socket-level stream, which may carry several keep-alive HTTP messages back to back.
    Body length is taken from Transfer-Encoding: chunked, else Content-Length, else the rest of the
    stream. Returns [{headers, lower, body, offset}]; empty if the stream does not start with HTTP."""
    messages = []
    pos, n = 0, len(raw)
    while pos < n:
        sep = raw.find(b"\r\n\r\n", pos)
        if sep < 0:
            break
        head = raw[pos:sep]
        firstLine = head.split(b"\r\n", 1)[0]
        if not (firstLine.startswith(b"HTTP/") or b" HTTP/" in firstLine):
            break
        headersText = head.decode("latin-1", "replace")
        lowerHead = headersText.lower()
        bodyStart = sep + 4

        if "transfer-encoding: chunked" in lowerHead:
            body, consumed = DeChunk(raw[bodyStart:])
            bodyEnd = bodyStart + consumed
        else:
            length = HeaderValue(lowerHead, "content-length:")
            try:
                length = int(length)
            except ValueError:
                length = None
            if length is not None:
                body = raw[bodyStart:bodyStart + length]
                bodyEnd = bodyStart + length
            else:
                body, bodyEnd = raw[bodyStart:], n

        encoding = HeaderValue(lowerHead, "content-encoding:")
        if encoding:
            body = Decompress(body, encoding)

        messages.append({"headers": headersText, "lower": lowerHead, "body": body, "offset": bodyStart})
        if bodyEnd <= pos:  # no forward progress means a malformed length; stop rather than spin
            break
        pos = bodyEnd
    return messages


# -- conversation assembly --------------------------------------------------
def _Endpoint(address, port):
    address = str(address or "")
    port = str(port or "")
    if address and port:
        return f"{address}:{port}"
    return address or port or "?"


def _FileName(lowerHead, headersText):
    # filename="x" from Content-Disposition, matched case-insensitively but sliced from the original
    # header text so the returned name keeps its case.
    marker = "filename="
    idx = lowerHead.find(marker)
    if idx < 0:
        return ""
    value = headersText[idx + len(marker):].split("\r\n", 1)[0].strip().strip('";')
    return value


def _LooksLikeFile(contentType, lowerHead):
    if "attachment" in lowerHead or "filename=" in lowerHead:
        return True
    if contentType.startswith("image/"):
        return True
    return contentType.split(";", 1)[0].strip() in FILE_CONTENT_TYPES


def _StreamBytes(analysisDir, events, cache):
    """Concatenate one direction's payload in log order: inline text -> utf-8 bytes, buffered chunk ->
    the [offset:offset+bytes] slice of files/<sha256>. Faithful across the inline/file split."""
    out = bytearray()
    for ev in events:
        body = ev.get("body")
        if not isinstance(body, dict):
            continue
        sha256 = ev.get("sha256")
        if body.get("stream") and sha256:
            if sha256 not in cache:
                data = b""
                path = os.path.join(analysisDir, "files", sha256)
                if path_exists(path):
                    try:
                        with open(path, "rb") as fd:
                            data = fd.read()
                    except Exception:
                        data = b""
                cache[sha256] = data
            raw = cache[sha256]
            offset = int(body.get("offset", 0) or 0)
            size = int(body.get("bytes", 0) or 0)
            out += raw[offset:offset + size] if size else raw[offset:]
        elif body.get("text") is not None:
            out += str(body["text"]).encode("utf-8", "replace")
    return bytes(out)


def _RenderMessage(direction, msg, drops, connLabel):
    """Render one HTTP message into detail-pane sections and, when the body is a file, queue a drop.
    Returns the joined section text."""
    body = msg["body"]
    lower = msg["lower"]
    contentType = HeaderValue(lower, "content-type:")
    sections = [_Block(f"{direction} headers", msg["headers"])]
    if not body:
        sections.append(f"{direction} body: (empty)")
        return "\n\n".join(sections)

    if IsProbablyText(body):
        sections.append(_Block(f"{direction} body", body.decode("utf-8", "replace")[:BODY_TEXT_CAP]))
        return "\n\n".join(sections)

    # Binary body: note it, preview it, and drop it as a file.
    filename = _FileName(lower, msg["headers"])
    drops.append({"bytes": body, "filename": filename, "content_type": contentType, "conn": connLabel})
    sha256 = hashlib.sha256(body).hexdigest()
    note = f"{direction} body: <binary, {len(body)} bytes, {contentType or 'unknown type'}> dropped as files/{sha256}"
    sections.append(note + "\n" + HexPreview(body[:HEX_PREVIEW]))
    return "\n\n".join(sections)


def _MaybeDropTextFile(direction, msg, drops, connLabel):
    # A text body can still be a file when the headers say so (attachment / file Content-Type).
    body = msg["body"]
    lower = msg["lower"]
    contentType = HeaderValue(lower, "content-type:")
    if body and _LooksLikeFile(contentType, lower):
        drops.append(
            {"bytes": body, "filename": _FileName(lower, msg["headers"]), "content_type": contentType, "conn": connLabel}
        )


def _BuildConversation(conn, analysisDir):
    connect = conn["connect"] or {}
    endpoints = conn["endpoints"] or {}
    transport = (connect.get("transport") or endpoints.get("transport")
                 or (conn["send"][0].get("transport") if conn["send"] else "")
                 or (conn["recv"][0].get("transport") if conn["recv"] else "") or "tcp")

    src = _Endpoint(endpoints.get("local_address"), endpoints.get("local_port"))
    dst = _Endpoint(endpoints.get("remote_address") or connect.get("host"),
                    endpoints.get("remote_port") or connect.get("port"))
    connLabel = f"{src} -> {dst}"

    cache = {}
    sent = _StreamBytes(analysisDir, conn["send"], cache)
    recv = _StreamBytes(analysisDir, conn["recv"], cache)
    requests = SplitHttpMessages(sent)
    responses = SplitHttpMessages(recv)

    drops = []
    sections = []
    for msg in requests:
        if IsProbablyText(msg["body"]):
            _MaybeDropTextFile("Sent", msg, drops, connLabel)
        sections.append(_RenderMessage("Sent", msg, drops, connLabel))
    for msg in responses:
        if IsProbablyText(msg["body"]):
            _MaybeDropTextFile("Received", msg, drops, connLabel)
        sections.append(_RenderMessage("Received", msg, drops, connLabel))

    if not requests and sent:
        sections.append(_NonHttpSection("Sent", sent))
    if not responses and recv:
        sections.append(_NonHttpSection("Received", recv))

    for err in conn["errors"]:
        sections.append(f"Error: {err.get('error', '')}")

    summary = _FormatDetail(
        [
            ("Transport", transport),
            ("Source", src),
            ("Destination", dst),
            ("Sent", f"{len(sent)} bytes, {len(requests)} HTTP message(s)"),
            ("Received", f"{len(recv)} bytes, {len(responses)} HTTP message(s)"),
        ]
    )
    detail = summary + ("\n\n" + "\n\n".join(sections) if sections else "")

    info = f"{transport}: {len(requests)} sent / {len(responses)} recv"
    record = {
        "kind": "Conversation",
        "conn_id": conn["conn_id"],
        "ts": conn.get("ts") or "",
        "src": src,
        "dst": dst,
        "transport": transport,
        "info": info,
        "detail": detail,
    }
    return record, drops


def _NonHttpSection(direction, raw):
    if IsProbablyText(raw):
        return _Block(f"{direction} (raw)", raw.decode("utf-8", "replace")[:BODY_TEXT_CAP])
    return f"{direction} (raw): <binary, {len(raw)} bytes>\n" + HexPreview(raw[:HEX_PREVIEW])


def AssembleConversations(jslog, analysisDir):
    """Group tcp_* events by conn_id and reconstruct each connection. Returns (conversations, drops).
    File I/O for the drops is left to DropExtractedFiles so this stays pure and testable."""
    events = (jslog or {}).get("events") or []
    conns = {}
    order = 0
    for ev in events:
        name = ev.get("event")
        if name not in ("tcp_connect", "tcp_endpoints", "tcp_send", "tcp_receive", "tcp_error"):
            continue
        cid = ev.get("conn_id")
        if cid is None:
            cid = f"noid:{order}"  # pre-conn_id logs: keep each orphan event as its own group
        conn = conns.get(cid)
        if conn is None:
            conn = {"conn_id": cid, "connect": None, "endpoints": None,
                    "send": [], "recv": [], "errors": [], "order": order, "ts": ev.get("ts")}
            conns[cid] = conn
        order += 1
        if name == "tcp_connect":
            conn["connect"] = ev
        elif name == "tcp_endpoints":
            conn["endpoints"] = ev
        elif name == "tcp_send":
            conn["send"].append(ev)
        elif name == "tcp_receive":
            conn["recv"].append(ev)
        elif name == "tcp_error":
            conn["errors"].append(ev)

    conversations = []
    drops = []
    for conn in sorted(conns.values(), key=lambda c: c["order"]):
        record, cdrops = _BuildConversation(conn, analysisDir)
        conversations.append(record)
        drops.extend(cdrops)
    return conversations, drops


def AssembleDns(jslog):
    """Pair dns_query / dns_result / dns_error by request_id into one row per lookup."""
    events = (jslog or {}).get("events") or []
    lookups = {}
    order = 0
    for ev in events:
        name = ev.get("event")
        if name not in ("dns_query", "dns_result", "dns_error"):
            continue
        rid = ev.get("request_id")
        if rid is None:
            rid = f"noid:{order}"
        entry = lookups.get(rid)
        if entry is None:
            entry = {"host": "", "query_type": "", "answers": None, "error": "",
                     "ts": ev.get("ts") or "", "order": order}
            lookups[rid] = entry
        order += 1
        if ev.get("host"):
            entry["host"] = ev["host"]
        if ev.get("query_type"):
            entry["query_type"] = ev["query_type"]
        if name == "dns_result":
            entry["answers"] = ev.get("result")
        elif name == "dns_error":
            entry["error"] = ev.get("error", "")

    rows = []
    for entry in sorted(lookups.values(), key=lambda e: e["order"]):
        answers = entry["answers"]
        if isinstance(answers, dict):
            answers = answers.get("text", "")
        answersText = "" if answers is None else str(answers)
        info = " ".join(p for p in (entry["query_type"], entry["host"], answersText, entry["error"]) if p)
        detail = _FormatDetail(
            [
                ("Query type", entry["query_type"]),
                ("Host", entry["host"]),
                ("Answers", answersText),
                ("Error", entry["error"]),
            ]
        )
        rows.append({"kind": "DNS", "ts": entry["ts"], "src": "", "dst": entry["host"],
                     "info": info, "detail": detail})
    return rows


# -- file dropping ----------------------------------------------------------
def DropExtractedFiles(analysisDir, drops):
    """Write each reconstructed file body to files/<sha256> and register it in files.json exactly like
    configs_panel.DumpParserFiles, so it appears in Payloads and is YARA-scanned. Content-addressed:
    an existing sha256 is skipped (no duplicate bytes or files.json line). Returns new relPaths."""
    newPaths = []
    filesDir = os.path.join(analysisDir, "files")
    jsonPath = os.path.join(analysisDir, "files.json")
    for drop in drops:
        data = drop.get("bytes") or b""
        if not data:
            continue
        sha256 = hashlib.sha256(data).hexdigest()
        dest = os.path.join(filesDir, sha256)
        if path_exists(dest):
            continue  # already dropped (by the guest or an earlier pass) - do not duplicate the entry
        try:
            os.makedirs(filesDir, exist_ok=True)
            with open(dest, "wb") as fd:
                fd.write(data)
            contentType = drop.get("content_type") or "unknown"
            entry = {
                "path": f"files/{sha256}",
                "filepath": drop.get("filename") or "",
                "pids": [],
                "ppids": [],
                "metadata": f"js_console reconstructed body ({contentType})",
                "category": "files",
            }
            with open(jsonPath, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            newPaths.append(f"files/{sha256}")
        except Exception as e:
            log.warning("js_streams: failed to drop reconstructed file %s: %s", sha256, e)
    return newPaths
