"""Tests for user-assigned address names in the interactive debugger.

CAPEsolo.capelib.symbol_names is deliberately free of wx imports so these run without a GUI:

    ./.venv/Scripts/python.exe -m pytest tests/test_symbol_names.py
"""

from CAPEsolo.capelib.symbol_names import (
    NAMES_FILENAME,
    Absolute,
    FormatNames,
    IsValidName,
    LoadNames,
    ModuleOffset,
    NamesPath,
    ParseNames,
    SaveNames,
)

# (start, end, name) - the shape BuildModuleRanges produces, sorted by start.
RANGES = [
    (0x140000000, 0x140009000, "sample.exe"),
    (0x7FFB00000000, 0x7FFB00200000, "ntdll.dll"),
]


def test_module_offset_for_an_address_inside_a_module():
    assert ModuleOffset(0x140001374, RANGES) == ("sample.exe", 0x1374)
    assert ModuleOffset(0x140000000, RANGES) == ("sample.exe", 0)
    assert ModuleOffset(0x7FFB0009A210, RANGES) == ("ntdll.dll", 0x9A210)


def test_module_offset_is_none_outside_every_module():
    """Freshly allocated shellcode has no module to measure an offset against."""
    assert ModuleOffset(0x1A2F0000, RANGES) is None
    assert ModuleOffset(0x140009000, RANGES) is None      # one past the end
    assert ModuleOffset(0x13FFFFFFF, RANGES) is None      # one before the start
    assert ModuleOffset(0x140001374, []) is None


def test_absolute_round_trips_with_module_offset():
    for addr in (0x140001374, 0x140000000, 0x7FFB0009A210):
        mod, off = ModuleOffset(addr, RANGES)
        assert Absolute(mod, off, RANGES) == addr


def test_absolute_follows_a_module_to_a_new_base():
    """The reason names are stored as offsets: the same sample can load elsewhere."""
    moved = [(0x150000000, 0x150009000, "sample.exe")]
    assert Absolute("sample.exe", 0x1374, moved) == 0x150001374


def test_absolute_is_none_when_the_module_is_not_loaded():
    assert Absolute("nowhere.dll", 0x10, RANGES) is None


def test_absolute_is_none_when_the_offset_runs_past_the_module():
    assert Absolute("sample.exe", 0x9000, RANGES) is None
    assert Absolute("sample.exe", 0x100000, RANGES) is None


def test_absolute_matches_the_module_name_case_insensitively():
    """Module lists and user input disagree about case more often than not."""
    assert Absolute("SAMPLE.EXE", 0x1374, RANGES) == 0x140001374
    assert Absolute("Ntdll.DLL", 0x10, RANGES) == 0x7FFB00000010


def test_names_round_trip_through_the_file_format():
    names = {("sample.exe", 0x1374): "DecryptConfig", ("ntdll.dll", 0x9A210): "suspicious_stub"}
    assert ParseNames(FormatNames(names)) == names


def test_parse_accepts_an_offset_with_or_without_0x():
    assert ParseNames("sample.exe+0x1374 A") == {("sample.exe", 0x1374): "A"}
    assert ParseNames("sample.exe+1374 A") == {("sample.exe", 0x1374): "A"}


def test_parse_skips_comments_and_blank_lines():
    text = "# a comment\n\n   \nsample.exe+0x10 Real\n# another\n"
    assert ParseNames(text) == {("sample.exe", 0x10): "Real"}


def test_parse_skips_malformed_lines_without_losing_the_good_ones():
    text = (
        "sample.exe+0x10 Good\n"
        "no plus sign here\n"
        "sample.exe+0xZZ Bad\n"
        "sample.exe+0x20\n"            # no name
        "sample.exe+0x30 Also_good\n"
    )
    assert ParseNames(text) == {("sample.exe", 0x10): "Good", ("sample.exe", 0x30): "Also_good"}


def test_parse_rejects_a_name_it_could_not_read_back():
    # A leading digit or punctuation would not survive being re-read as a symbol.
    assert ParseNames("sample.exe+0x10 9lives") == {}
    assert ParseNames("sample.exe+0x10 has-a-dash") == {}


def test_valid_names():
    for good in ("main", "_start", "DecryptConfig", "sub.helper", "x", "a@b", "with$dollar", "n9"):
        assert IsValidName(good), good
    for bad in ("", "9lives", "has space", "has-dash", "a" * 65, None):
        assert not IsValidName(bad), bad


def test_formatted_file_is_stable_between_writes():
    """Sorted output, so re-saving the same names does not churn the file."""
    names = {("z.dll", 0x1): "Z", ("a.exe", 0x20): "B", ("a.exe", 0x10): "A"}
    once = FormatNames(names)
    assert once == FormatNames(dict(reversed(list(names.items()))))
    assert once.index("a.exe+0x10") < once.index("a.exe+0x20") < once.index("z.dll")


def test_path_is_under_the_analysis_debugger_directory():
    p = NamesPath(r"C:\analysis")
    assert p.name == NAMES_FILENAME
    assert p.parent.name == "debugger"
    assert NamesPath(None) is None
    assert NamesPath("") is None


def test_save_then_load(tmp_path):
    names = {("sample.exe", 0x1374): "DecryptConfig"}
    assert SaveNames(tmp_path, names) is True
    assert NamesPath(tmp_path).exists()
    assert LoadNames(tmp_path) == names


def test_load_with_no_file_yet_is_empty_not_an_error(tmp_path):
    assert LoadNames(tmp_path) == {}


def test_save_without_an_analysis_directory_reports_failure():
    assert SaveNames(None, {("a", 1): "B"}) is False


def test_save_overwrites_rather_than_appending(tmp_path):
    SaveNames(tmp_path, {("a.exe", 0x10): "First"})
    SaveNames(tmp_path, {("a.exe", 0x20): "Second"})
    assert LoadNames(tmp_path) == {("a.exe", 0x20): "Second"}
