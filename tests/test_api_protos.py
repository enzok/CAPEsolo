"""Tests for API prototype parsing.

CAPEsolo.capelib.api_protos is deliberately free of wx imports so these run without a GUI:

    ./.venv/Scripts/python.exe -m pytest tests/test_api_protos.py
"""

from CAPEsolo.capelib.api_protos import (
    LoadPrototypes,
    ParseParam,
    ParsePrototype,
    ParsePrototypes,
    SplitParams,
)


def test_single_parameter_as_the_docs_write_it():
    proto = ParsePrototype(
        """
        DWORD GetProcessVersion(
          [in] DWORD ProcessId
        );
        """
    )
    assert proto.name == "GetProcessVersion"
    assert proto.returnType == "DWORD"
    assert [(p.type, p.name, p.direction) for p in proto.params] == [("DWORD", "ProcessId", "in")]


def test_several_parameters_with_optional_out_annotations():
    proto = ParsePrototype(
        """
        BOOL GetSystemTimes(
          [out, optional] PFILETIME lpIdleTime,
          [out, optional] PFILETIME lpKernelTime,
          [out, optional] PFILETIME lpUserTime
        );
        """
    )
    assert proto.name == "GetSystemTimes"
    assert proto.returnType == "BOOL"
    assert [p.name for p in proto.params] == ["lpIdleTime", "lpKernelTime", "lpUserTime"]
    assert {p.direction for p in proto.params} == {"out"}
    assert {p.type for p in proto.params} == {"PFILETIME"}


def test_calling_convention_and_pointers_are_stripped_from_the_name():
    proto = ParsePrototype("LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);")
    assert proto.name == "VirtualAlloc"
    assert proto.returnType == "LPVOID"
    assert [p.name for p in proto.params] == ["lpAddress", "dwSize", "flAllocationType", "flProtect"]


def test_underscore_sal_from_a_header():
    proto = ParsePrototype(
        "BOOL WINAPI WriteProcessMemory(_In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress,"
        " _In_reads_bytes_(nSize) LPCVOID lpBuffer, _In_ SIZE_T nSize,"
        " _Out_opt_ SIZE_T *lpNumberOfBytesWritten);"
    )
    assert [p.name for p in proto.params] == [
        "hProcess", "lpBaseAddress", "lpBuffer", "nSize", "lpNumberOfBytesWritten"
    ]
    assert proto.params[0].direction == "in"
    assert proto.params[4].direction == "out"


def test_pointer_star_does_not_become_part_of_the_name():
    proto = ParsePrototype("BOOL F(DWORD *pOut, LPVOID* pBuf, char **argv);")
    assert [p.name for p in proto.params] == ["pOut", "pBuf", "argv"]


def test_array_suffix_stays_out_of_the_name():
    proto = ParsePrototype("void F(BYTE buf[16], DWORD n);")
    assert [p.name for p in proto.params] == ["buf", "n"]


def test_void_parameter_list_means_no_arguments():
    assert ParsePrototype("BOOL IsDebuggerPresent(void);").params == []
    assert ParsePrototype("DWORD GetLastError(VOID);").params == []
    assert ParsePrototype("DWORD GetTickCount();").params == []


def test_inout_direction():
    proto = ParsePrototype("NTSTATUS F([in, out] PULONG Size);")
    assert proto.params[0].direction == "inout"


def test_a_type_with_no_parameter_name_still_yields_a_parameter():
    """Some docs give only the type for a single argument; it still occupies a position."""
    proto = ParsePrototype("void free(void *);")
    assert len(proto.params) == 1


def test_missing_trailing_semicolon_is_accepted():
    """A declaration pasted from a docs page may not include it."""
    proto = ParsePrototype("DWORD GetProcessVersion(\n  [in] DWORD ProcessId\n)")
    assert proto is not None
    assert proto.params[0].name == "ProcessId"


def test_comments_are_ignored():
    proto = ParsePrototype("/* allocate */ LPVOID VirtualAlloc(LPVOID lpAddress, // where\n SIZE_T dwSize);")
    assert proto.name == "VirtualAlloc"
    assert [p.name for p in proto.params] == ["lpAddress", "dwSize"]


def test_rubbish_is_rejected_rather_than_guessed_at():
    assert ParsePrototype("") is None
    assert ParsePrototype("   ") is None
    assert ParsePrototype("not a declaration at all") is None
    assert ParsePrototype("DWORD x = 1;") is None


def test_split_params_respects_nesting():
    assert SplitParams("_In_reads_(a, b) X y, Z w") == ["_In_reads_(a, b) X y", "Z w"]
    assert SplitParams("[in, optional] A a, [out] B b") == ["[in, optional] A a", "[out] B b"]


def test_parse_param_rejects_an_empty_declaration():
    assert ParseParam("") is None
    assert ParseParam("void") is None


def test_many_declarations_from_one_block():
    protos = ParsePrototypes(
        """
        DWORD GetProcessVersion([in] DWORD ProcessId);
        BOOL GetSystemTimes([out, optional] PFILETIME lpIdleTime);
        BOOL IsDebuggerPresent(void);
        """
    )
    assert set(protos) == {"GetProcessVersion", "GetSystemTimes", "IsDebuggerPresent"}
    assert protos["GetProcessVersion"].params[0].name == "ProcessId"


def test_the_packaged_table_parses_and_has_the_apis_that_matter():
    """Guards the shipped file against a typo silently dropping a declaration."""
    protos = LoadPrototypes()
    for api in ("VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateFileW",
                "NtAllocateVirtualMemory", "LoadLibraryW", "GetProcAddress", "CreateProcessW"):
        assert api in protos, f"{api} missing from the packaged prototype table"

    assert [p.name for p in protos["VirtualAlloc"].params] == [
        "lpAddress", "dwSize", "flAllocationType", "flProtect"
    ]
    # Every declaration in the file must have produced at least a name.
    assert all(proto.name for proto in protos.values())
