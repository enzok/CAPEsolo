import json
import logging
from pathlib import Path

from .path_utils import path_exists

log = logging.getLogger(__name__)

LOG_NAME = "js_console.log"
MAX_LOG_CHARS = 64 * 1024

# Event types the report buckets by name. The interceptor emits more than these (dns_*,
# tcp_*, socket_*, module_intercept*, eval); those stay in "events" only, which is what
# the panel groups off, so nothing is hidden by the shorter list here.
EVENT_KEYS = {
    "http_request": "http_requests",
    "http_response": "http_responses",
    "http_error": "http_errors",
    "console": "console",
    "warning": "warnings",
    "init": "init",
}


def ParseJsLog(logPath):
    """Parse the JSON lines written by the js_console interceptor.
    @return: events, total lines, parsed lines, malformed lines, truncated
    """
    events = []
    totalLines = 0
    parsedLines = 0
    malformedLines = 0
    # Retained for backward compatibility with callers and the report schema; every line
    # is now parsed, so this is always False.
    truncated = False

    try:
        with open(logPath, "r", encoding="utf-8", errors="replace") as hfile:
            for line in hfile:
                totalLines += 1
                text = line.strip()
                if not text:
                    continue

                try:
                    events.append(json.loads(text))
                    parsedLines += 1
                except json.JSONDecodeError:
                    malformedLines += 1
    except Exception as e:
        log.warning("Failed to parse JS log file %s: %s", logPath, e)

    return events, totalLines, parsedLines, malformedLines, truncated


def GetJsLogPath(analysisDir):
    """Locate the uploaded log. The result server rewrites the "aux" prefix the analyzer
    sends to "aux_", so the log lands under aux_/js_console rather than aux/js_console.
    """
    auxDir = Path(analysisDir) / "aux_"
    logPath = auxDir / "js_console" / LOG_NAME
    if not path_exists(str(logPath)):
        logPath = auxDir / LOG_NAME

    return logPath


def JsLog(analysisDir):
    """Process the js_console log into report results."""
    logPath = GetJsLogPath(analysisDir)
    output = {
        "path": str(logPath),
        "exists": False,
        "log": "",
        "total_lines": 0,
        "parsed_lines": 0,
        "malformed_lines": 0,
        "truncated": False,
        "events": [],
        "http_requests": [],
        "http_responses": [],
        "http_errors": [],
        "console": [],
        "warnings": [],
        "init": [],
        "buffers": [],
    }

    if not path_exists(str(logPath)):
        return output

    output["exists"] = True

    try:
        rawLog = logPath.read_text(encoding="utf-8", errors="replace")
        if len(rawLog) > MAX_LOG_CHARS:
            output["log"] = rawLog[:MAX_LOG_CHARS] + "\r\n... [TRUNCATED - LOG TOO LARGE] ..."
        else:
            output["log"] = rawLog

        events, totalLines, parsedLines, malformedLines, truncated = ParseJsLog(
            logPath
        )
        output["total_lines"] = totalLines
        output["parsed_lines"] = parsedLines
        output["malformed_lines"] = malformedLines
        output["truncated"] = truncated
        output["events"] = events

        for event in events:
            key = EVENT_KEYS.get(event.get("event"))
            if key:
                output[key].append(event)

        # Link tcp_send/tcp_receive events to the dropped buffer files. The interceptor streams large
        # TCP payloads to per-stream files and logs a {stream, bytes, offset} reference; the aux module
        # hashes each and writes js_buffers.json (stream -> sha256), uploading the bytes as
        # files/<sha256>. Stamp the sha256 onto matching events so the report can resolve them.
        manifestPath = logPath.parent / "js_buffers.json"
        if path_exists(str(manifestPath)):
            try:
                manifest = json.loads(manifestPath.read_text(encoding="utf-8", errors="replace"))
                streamMap = {
                    entry["stream"]: {"sha256": entry.get("sha256"), "bytes": entry.get("bytes")}
                    for entry in manifest
                    if entry.get("stream")
                }
                output["buffers"] = [{"stream": s, **info} for s, info in streamMap.items()]
                for event in events:
                    if event.get("event") in ("tcp_send", "tcp_receive"):
                        body = event.get("body")
                        if isinstance(body, dict):
                            info = streamMap.get(body.get("stream"))
                            if info and info.get("sha256"):
                                event["sha256"] = info["sha256"]
            except Exception as e:
                log.warning("js_log: failed to read buffer manifest %s: %s", manifestPath, e)
    except Exception as e:
        log.warning("js_log failed on %s: %s", logPath, e)

    return output
