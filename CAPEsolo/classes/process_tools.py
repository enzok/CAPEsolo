"""External (out-of-process) controls for analysis processes, used by the Process Tree window.

Everything here acts on a PID from OUTSIDE the target - Toolhelp32 enumeration and Win32/NT calls
made by the GUI process (CAPEsolo runs the sample in-process, so the GUI shares the OS with it).
Nothing here injects, hooks, patches or writes into the monitored processes, so capemon's hooks are
left untouched. Terminate prefers capemon's own cooperative terminate-event (the monitor flushes and
self-exits) and only force-kills a process capemon is not monitoring.

Handles are opened with exactly the rights each op needs and closed in a finally - we deliberately do
not reuse lib.api.process.Process.open(), which caches the handle (leaking one per call) and silently
falls back to PROCESS_QUERY_LIMITED_INFORMATION, turning an access failure into a confusing later error.
"""

import ctypes
import time
from ctypes import byref, sizeof, wintypes
from pathlib import Path

# Import via the SAME top-level spelling the analyzer uses (`lib.common...`, per analyzer.py:30 and
# lib/api/process.py:46), NOT `CAPEsolo.lib.common...`. TERMINATE_EVENT is a per-import random prefix;
# the two spellings are distinct module objects with distinct values, so importing the wrong one would
# make our cooperative-terminate signal miss capemon's event and silently fall through to a hard kill.
from lib.common.constants import TERMINATE_EVENT
from lib.common.defines import (
    EVENT_MODIFY_STATE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESSENTRY32,
    STILL_ACTIVE,
)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
MINIDUMP_WITH_FULL_MEMORY = 0x00000002
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Private library instances with explicit prototypes, so setting argtypes/restype here cannot
# disturb the shared handles in lib.common.defines that the analyzer relies on. restype must be
# HANDLE (c_void_p) or 64-bit handles get truncated to c_int and fail.
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll")
_dbghelp = None  # loaded lazily on first dump

_k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_k32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_k32.Process32First.restype = wintypes.BOOL
_k32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_k32.Process32Next.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
_k32.OpenEventW.restype = wintypes.HANDLE
_k32.SetEvent.argtypes = [wintypes.HANDLE]
_k32.SetEvent.restype = wintypes.BOOL
_k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k32.TerminateProcess.restype = wintypes.BOOL
_k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_k32.GetExitCodeProcess.restype = wintypes.BOOL
_k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
_k32.CreateFileW.restype = wintypes.HANDLE

_ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
_ntdll.NtSuspendProcess.restype = ctypes.c_long
_ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
_ntdll.NtResumeProcess.restype = ctypes.c_long


def _err():
    return ctypes.get_last_error()


def snapshot_processes():
    """{pid: (ppid, name)} for every process on the system, via Toolhelp32. Read-only, external."""
    result = {}
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return result
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = sizeof(PROCESSENTRY32)
        ok = _k32.Process32First(snap, byref(entry))
        while ok:
            name = entry.sz_exeFile.decode(errors="replace")
            result[entry.th32ProcessID] = (entry.th32ParentProcessID, name)
            ok = _k32.Process32Next(snap, byref(entry))
    finally:
        _k32.CloseHandle(snap)
    return result


def _is_alive(pid):
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wintypes.DWORD(0)
        if _k32.GetExitCodeProcess(h, byref(code)):
            return code.value == STILL_ACTIVE
        return False
    finally:
        _k32.CloseHandle(h)


def _nt_process_op(pid, fn, what):
    h = _k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h:
        raise OSError(f"OpenProcess(SUSPEND_RESUME) failed for pid {pid} (error {_err()})")
    try:
        status = fn(h)
        if status < 0:
            raise OSError(f"{what} failed for pid {pid} (NTSTATUS {status & 0xFFFFFFFF:#010x})")
        return True
    finally:
        _k32.CloseHandle(h)


def suspend_process(pid):
    return _nt_process_op(pid, _ntdll.NtSuspendProcess, "NtSuspendProcess")


def resume_process(pid):
    return _nt_process_op(pid, _ntdll.NtResumeProcess, "NtResumeProcess")


def _signal_terminate_event(pid):
    """Signal capemon's per-process terminate-event so the monitor flushes and self-exits. Returns
    True if the event existed (a monitored process). TERMINATE_EVENT is the same random prefix the
    analyzer configured capemon with - shared because the analyzer runs in this process."""
    handle = _k32.OpenEventW(EVENT_MODIFY_STATE, False, f"{TERMINATE_EVENT}{pid}")
    if not handle:
        return False
    try:
        return bool(_k32.SetEvent(handle))
    finally:
        _k32.CloseHandle(handle)


def terminate_process(pid):
    """Cooperative capemon shutdown first, hard kill only as fallback. Returns "cooperative" or
    "forced". Blocking (waits briefly for the cooperative exit) - call off the UI thread."""
    cooperative = _signal_terminate_event(pid)
    if cooperative:
        for _ in range(30):  # up to ~3s for capemon to flush and exit
            time.sleep(0.1)
            if not _is_alive(pid):
                return "cooperative"

    h = _k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        if cooperative:
            # We signalled it and can't open it to kill - assume it is on its way out.
            return "cooperative"
        raise OSError(f"OpenProcess(TERMINATE) failed for pid {pid} (error {_err()})")
    try:
        if not _k32.TerminateProcess(h, 1):
            raise OSError(f"TerminateProcess failed for pid {pid} (error {_err()})")
        return "forced"
    finally:
        _k32.CloseHandle(h)


def _get_dbghelp():
    global _dbghelp
    if _dbghelp is None:
        _dbghelp = ctypes.WinDLL("dbghelp")
        _dbghelp.MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
        ]
        _dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
    return _dbghelp


def dump_process_memory(pid, dest):
    """Write a full minidump of pid to dest. Returns the path or raises. Blocking and potentially
    large (>500 MB) - call off the UI thread."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    h = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError(f"OpenProcess for dump failed for pid {pid} (error {_err()})")
    try:
        h_file = _k32.CreateFileW(
            str(dest), GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
        )
        if not h_file or h_file == INVALID_HANDLE_VALUE:
            raise OSError(f"CreateFile failed for {dest} (error {_err()})")
        try:
            dbghelp = _get_dbghelp()
            if not dbghelp.MiniDumpWriteDump(
                h, pid, h_file, MINIDUMP_WITH_FULL_MEMORY, None, None, None
            ):
                raise OSError(f"MiniDumpWriteDump failed for pid {pid} (error {_err()})")
        finally:
            _k32.CloseHandle(h_file)
    finally:
        _k32.CloseHandle(h)
    return str(dest)
