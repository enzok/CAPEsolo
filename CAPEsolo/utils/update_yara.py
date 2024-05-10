import re
from pathlib import Path

import requests


def download_and_update_yara_files(yara_path, yara_url, yara_raw_url):
    yara_file_names = set()
    yara_regex = r"([\w\-\d]+\.yar)"

    # Fetch YARA rule names from GitHub
    resp = requests.get(yara_url)
    page_content = resp.json().get("payload", {}).get("tree", {}).get("items", [])
    for line in page_content:
        if line:
            match = re.search(yara_regex, line["name"])
            if match:
                yara_file_names.add(match.group(0))

    # Delete existing YARA files
    for f in yara_path.glob("*"):
        f.unlink()

    # Download and write new YARA rules
    for file_name in sorted(yara_file_names):
        file_content = requests.get(yara_raw_url.format(file_name)).text
        yara_file_path = yara_path / file_name
        with open(yara_file_path, "w") as f:
            f.write(file_content)
        print(f"Successfully downloaded and wrote {yara_file_path}!")


def update_yara(root_path):
    yara_paths = [
        {
            "yara_path": root_path / "data/yararules/CAPE",
            "yara_url": "https://github.com/kevoreilly/CAPEv2/tree/master/data/yara/CAPE",
            "yara_raw_url": "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/data/yara/CAPE/{0}",
        },
        {
            "yara_path": root_path / "data/yararules/CAPEc",
            "yara_url": "https://github.com/CAPESandbox/community/tree/master/data/yara/CAPE",
            "yara_raw_url": "https://raw.githubusercontent.com/CAPESandbox/community/master/data/yara/CAPE/{0}",
        },
        {
            "yara_path": root_path / "data/yara",
            "yara_url": "https://github.com/kevoreilly/CAPEv2/tree/master/analyzer/windows/data/yara",
            "yara_raw_url": "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/{0}",
        }
    ]

    for config in yara_paths:
        download_and_update_yara_files(**config)


if __name__ == "__main__":
    import CAPEsolo

    update_yara(Path(CAPEsolo.__file__).parent)
