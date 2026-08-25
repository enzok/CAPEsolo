# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import operator
import re
from collections import defaultdict
from http import HTTPStatus
from pathlib import Path
from time import localtime, strftime

import requests

from .objects import File

log = logging.getLogger(__name__)

# https://docs.virustotal.com/v3/reference/files
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{id}"
# https://docs.virustotal.com/v3/reference/files-scan and get-files-upload-url
VIRUSTOTAL_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_UPLOAD_URL_LARGE = "https://www.virustotal.com/api/v3/files/upload_url"

# public VT key
key = "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088"
timeout = 60
upload_timeout = 300

# The plain upload endpoint caps at 32 MB; larger files need a one-off upload URL. VT rejects
# anything over 650 MB outright, so we stop before starting a doomed multi-hundred-MB transfer.
LARGE_FILE_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD_SIZE = 650 * 1024 * 1024

headers = {"x-apikey": key}


def get_vt_consensus(namelist: list):
    finaltoks = defaultdict(int)
    for name in namelist:
        toks = re.findall(r"[A-Za-z0-9]+", name)
        for tok in toks:
            finaltoks[tok.title()] += 1

    for tok in list(finaltoks):
        accepted = True
        numlist = [x for x in tok if x.isdigit()]
        if len(numlist) > 2 or len(tok) < 4:
            accepted = False

        if not accepted:
            del finaltoks[tok]

    sorted_finaltoks = sorted(finaltoks.items(), key=operator.itemgetter(1), reverse=True)
    if not sorted_finaltoks:
        return ""

    top = sorted_finaltoks[0][1]
    if len(sorted_finaltoks) == 1:
        return sorted_finaltoks[0][0] if top >= 2 else ""

    second = sorted_finaltoks[1][1]
    if top >= second * 2 or top > 8 or (top == second and top > 2):
        return sorted_finaltoks[0][0]

    return ""


def vt_lookup(target: str):
    sha256 = target if len(target) == 64 else File(target).get_sha256()
    url = VIRUSTOTAL_FILE_URL.format(id=sha256)

    try:
        r = requests.get(url, headers=headers, verify=True, timeout=timeout)
        if r.status_code == HTTPStatus.NOT_FOUND:
            log.info("'%s' not found in VT", url.split("/")[-1])
            return {"found": False}

        if r.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            log.error("VT: Rate limit")
            return {
                "error": True,
                "msg": "VirusTotal rate limit reached (the public key allows ~4 lookups/minute). Wait a minute and try again.",
            }

        if not r.ok:
            log.error("VT: Request failed")
            return {
                "error": True,
                "msg": f"Unable to complete connection to VirusTotal. Status code: {r.status_code}",
            }

        if b"QuotaExceededError" in r.content:
            log.error("VT: Quota limit")
            return {"error": True, "msg": "QuotaExceededError"}

        vt_response = r.json()
        attributes = vt_response.get("data", {}).get("attributes", {})
        engines = attributes.get("last_analysis_results", {})
        # On VT but not yet analysed: present (found), just nothing to report yet. Distinct from a
        # 404 so callers don't offer to re-upload a file that is already there.
        if not engines:
            log.info("VT: file present but analysis pending")
            return {
                "found": True,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }

        virustotal = {
            "found": True,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
        positives = attributes.get("last_analysis_stats", {}).get("malicious")
        if positives:
            virustotal["summary"] = f"{positives}/{len(engines)}"

        timeformat = "%a, %d %b %Y %H:%M:%S %Z"
        first_seen = attributes.get("first_submission_date")
        if first_seen:
            virustotal["first_seen"] = strftime(timeformat, localtime(first_seen))

        last_seen = attributes.get("last_submission_date")
        if last_seen:
            virustotal["last_seen"] = strftime(timeformat, localtime(last_seen))

        detectnames = []
        for engine, block in engines.items():
            result = block.get("result")
            if result and "Trojan.Heur." not in result:
                # weight Microsoft's detection, they seem to be more accurate than the rest
                if engine == "Microsoft":
                    detectnames.append(result)

                detectnames.append(result)

        virustotal["detection"] = get_vt_consensus(detectnames)
        return virustotal
    except requests.exceptions.RequestException as e:
        return {
            "error": True,
            "msg": f"Unable to complete connection to VirusTotal: {e}",
        }


def _upload_failure(r):
    if r.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        log.error("VT: Rate limit")
        return {
            "error": True,
            "msg": "VirusTotal rate limit reached (the public key allows ~4 uploads/minute). Wait a minute and try again.",
        }
    if r.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
        log.error("VT: upload rejected (%s)", r.status_code)
        return {
            "error": True,
            "msg": f"VirusTotal rejected the upload (status {r.status_code}); the public key may not permit uploads.",
        }
    log.error("VT: upload failed (%s)", r.status_code)
    return {"error": True, "msg": f"Upload failed. Status code: {r.status_code}"}


def vt_upload(target: str, sha256: str = ""):
    """Upload *target* to VirusTotal, making it publicly available. Returns the analysis id and a
    permalink on success, or an ``error``/``msg`` dict. sha256 (if known) avoids a re-hash."""
    path = Path(target)
    try:
        size = path.stat().st_size
    except OSError as e:
        return {"error": True, "msg": f"Cannot read file: {e}"}

    if size > MAX_UPLOAD_SIZE:
        return {"error": True, "msg": "File exceeds VirusTotal's 650 MB upload limit."}

    sha256 = sha256 or File(target).get_sha256()

    try:
        if size > LARGE_FILE_LIMIT:
            r = requests.get(
                VIRUSTOTAL_UPLOAD_URL_LARGE, headers=headers, verify=True, timeout=timeout
            )
            if not r.ok:
                return _upload_failure(r)
            upload_url = r.json().get("data")
        else:
            upload_url = VIRUSTOTAL_UPLOAD_URL

        with path.open("rb") as f:
            r = requests.post(
                upload_url,
                headers=headers,
                files={"file": (path.name, f)},
                verify=True,
                timeout=upload_timeout,
            )
        if not r.ok:
            return _upload_failure(r)

        analysis_id = r.json().get("data", {}).get("id", "")
        return {
            "analysis_id": analysis_id,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": True,
            "msg": f"Unable to complete connection to VirusTotal: {e}",
        }
