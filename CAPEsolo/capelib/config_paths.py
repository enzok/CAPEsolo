import os
from pathlib import Path

CONFIG_FILENAME = "cfg.ini"
CONFIG_ENV = "CAPESOLO_CFG"
DEFAULT_PUBLIC_DIR = r"C:\Users\Public"


def packaged_config_path() -> Path:
    """Path of the cfg.ini shipped inside the package. Overwritten by pip upgrades."""
    return Path(__file__).resolve().parent.parent / CONFIG_FILENAME


def user_config_path() -> Path:
    """Path of the user cfg.ini, which pip never touches.

    Honours CAPESOLO_CFG, otherwise sits next to the analysis directory in
    %PUBLIC%\\CAPEsolo so config lives beside the data it configures.
    """
    override = os.environ.get(CONFIG_ENV, "").strip()
    if override:
        return Path(override)

    public = os.environ.get("PUBLIC", "").strip() or DEFAULT_PUBLIC_DIR
    return Path(public) / "CAPEsolo" / CONFIG_FILENAME


def config_paths() -> list[Path]:
    """Config files in precedence order, lowest first, for configparser.read().

    Later files override earlier ones per key, and missing files are skipped, so the
    user file only needs the settings it actually changes.
    """
    return [packaged_config_path(), user_config_path()]
