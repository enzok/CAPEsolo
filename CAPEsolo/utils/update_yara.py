import json
import re
from pathlib import Path

import requests
from bs2json import BS2Json


def download_and_update_yara_files(yara_path, yara_url, yara_raw_url):
    yara_file_names = set()
    YARA_REGEX = r"([\w\-\d]+\.yar)"

    # Fetch YARA rule names from GitHub
    resp = requests.get(yara_url)
    resp.raise_for_status()  # raises exception when not a 2xx response
    if resp.status_code != 204:
        try:
            if resp.headers["content-type"].strip().startswith("application/json"):
                page_content = json.loads(resp.content).get("payload", {}).get("tree", {}).get("items", [])
            elif resp.headers["content-type"].strip().startswith("text/html"):
                bs2_json = BS2Json(resp.text)
                json_obj = bs2_json.convert()
                payload_text = json_obj["html"]["body"]["div"][0]["div"][3]["div"]["main"]["turbo-frame"]["div"]["react-app"]["script"][
                    "text"
                ]
                json_payload = json.loads(payload_text)
                page_content = json_payload.get("payload", {}).get("tree", {}).get("items", [])
            else:
                dataform = str(resp.content).strip("'<>() ").replace("'", '"')
                page_content = json.loads(dataform).get("payload", {}).get("tree", {}).get("items", [])

            for line in page_content:
                if not line:
                    continue

                match = re.search(YARA_REGEX, line["name"])
                if match:
                    yara_file_names.add(match.group(0))

        except Exception as e:
            print(e)

    # Delete existing YARA files
    for f in yara_path.glob("*"):
        f.unlink()

    # Download and write new YARA rules
    num = 0
    for file_name in sorted(yara_file_names):
        file_content = requests.get(yara_raw_url.format(file_name)).text
        yara_file_path = yara_path / file_name
        with open(yara_file_path, "w") as f:
            f.write(file_content)

        num += 1
        #print(f"Successfully downloaded and wrote {yara_file_path}!")

    return num


def UpdateYara(RootPath):
    results = {}
    YaraPaths = [
        {
            "yara_path": RootPath / "yara/CAPE",
            "yara_url": "https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE",
            "yara_raw_url": "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/data/yara/CAPE/{0}",
        },
        {
            "yara_path": RootPath / "yara/CAPE_community",
            "yara_url": "https://github.com/CAPESandbox/community/tree/master/data/yara/CAPE",
            "yara_raw_url": "https://raw.githubusercontent.com/CAPESandbox/community/master/data/yara/CAPE/{0}",
        },
        {
            "yara_path": RootPath / "data/yara",
            "yara_url": "https://github.com/kevoreilly/CAPEv2/tree/master/analyzer/windows/data/yara",
            "yara_raw_url": "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/{0}",
        }
    ]

    for config in YaraPaths:
        num = download_and_update_yara_files(**config)
        name = "/".join(config["yara_path"].parts[-2:])
        results[name] = num

    return results


if __name__ == "__main__":
    import CAPEsolo

    UpdateYara(Path(CAPEsolo.__file__).parent)
