import re
from pathlib import Path

import requests


def download_and_update_parser_files(parser_path, parser_url, parser_raw_url):
    parser_file_names = set()
    parser_regex = r"([\w\-\d]+\.py)"

    # Fetch parser names from GitHub
    resp = requests.get(parser_url)
    page_content = resp.json().get("payload", {}).get("tree", {}).get("items", [])
    for line in page_content:
        if line:
            match = re.search(parser_regex, line["name"])
            if (
                match
                and match.group(0) not in ["__init__.py"]
                and not match.group(0).startswith("test_")
            ):
                parser_file_names.add(match.group(0))

    # Delete existing parser files
    for f in parser_path.glob("*"):
        if not f.name != "__init__.py" and "test_" not in f.name:
            if f.isfile(f):
                print(f"Successfully deleted {f}!")
                f.unlink()

    # Download and write new parser files
    for file_name in sorted(parser_file_names):
        file_content = requests.get(parser_raw_url.format(file_name)).text
        parser_file_path = parser_path / file_name
        with open(parser_file_path, "w") as f:
            f.write(file_content)
        print(f"Successfully downloaded and wrote {parser_file_path}!")


def update_parsers(root_path):
    parser_paths = [
        {
            "parser_path": root_path / "parsers",
            "parser_url": "https://github.com/kevoreilly/CAPEv2/tree/master/modules/processing/parsers/CAPE",
            "parser_raw_url": "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/modules/processing/parsers/CAPE",
        },
    ]

    for config in parser_paths:
        download_and_update_parser_files(**config)


if __name__ == "__main__":
    import CAPEsolo

    update_parsers(Path(CAPEsolo.__file__).parent)
