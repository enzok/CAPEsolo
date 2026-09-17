/* API prototypes used to name call arguments in the interactive debugger's disassembly view.
 *
 * Declarations are in the form the documentation gives them, so one can be pasted in
 * unchanged. Parsed by CAPEsolo/capelib/api_protos.py.
 *
 * pip overwrites this file on upgrade. Additions made through "Add API Prototype..." in the
 * disassembly context menu go to api_prototypes.h beside the user cfg.ini instead, and a
 * declaration there overrides one here.
 *
 * Only what is wanted at a call site is recorded: the parameter names, in order, and their
 * types. A declaration with the wrong number of parameters mislabels every argument after
 * the mistake, so the count matters more than the spelling of any one type.
 */

/* ---- memory ---- */
LPVOID WINAPI VirtualAlloc([in, optional] LPVOID lpAddress, [in] SIZE_T dwSize, [in] DWORD flAllocationType, [in] DWORD flProtect);
LPVOID WINAPI VirtualAllocEx([in] HANDLE hProcess, [in, optional] LPVOID lpAddress, [in] SIZE_T dwSize, [in] DWORD flAllocationType, [in] DWORD flProtect);
BOOL WINAPI VirtualFree([in] LPVOID lpAddress, [in] SIZE_T dwSize, [in] DWORD dwFreeType);
BOOL WINAPI VirtualProtect([in] LPVOID lpAddress, [in] SIZE_T dwSize, [in] DWORD flNewProtect, [out] PDWORD lpflOldProtect);
BOOL WINAPI VirtualProtectEx([in] HANDLE hProcess, [in] LPVOID lpAddress, [in] SIZE_T dwSize, [in] DWORD flNewProtect, [out] PDWORD lpflOldProtect);
SIZE_T WINAPI VirtualQuery([in, optional] LPCVOID lpAddress, [out] PMEMORY_BASIC_INFORMATION lpBuffer, [in] SIZE_T dwLength);
BOOL WINAPI ReadProcessMemory([in] HANDLE hProcess, [in] LPCVOID lpBaseAddress, [out] LPVOID lpBuffer, [in] SIZE_T nSize, [out, optional] SIZE_T *lpNumberOfBytesRead);
BOOL WINAPI WriteProcessMemory([in] HANDLE hProcess, [in] LPVOID lpBaseAddress, [in] LPCVOID lpBuffer, [in] SIZE_T nSize, [out, optional] SIZE_T *lpNumberOfBytesWritten);
HANDLE WINAPI HeapCreate([in] DWORD dwOptions, [in] SIZE_T dwInitialSize, [in] SIZE_T dwMaximumSize);
LPVOID WINAPI HeapAlloc([in] HANDLE hHeap, [in] DWORD dwFlags, [in] SIZE_T dwBytes);
NTSTATUS NTAPI NtAllocateVirtualMemory([in] HANDLE ProcessHandle, [in, out] PVOID *BaseAddress, [in] ULONG_PTR ZeroBits, [in, out] PSIZE_T RegionSize, [in] ULONG AllocationType, [in] ULONG Protect);
NTSTATUS NTAPI NtProtectVirtualMemory([in] HANDLE ProcessHandle, [in, out] PVOID *BaseAddress, [in, out] PSIZE_T RegionSize, [in] ULONG NewProtect, [out] PULONG OldProtect);
NTSTATUS NTAPI NtWriteVirtualMemory([in] HANDLE ProcessHandle, [in] PVOID BaseAddress, [in] PVOID Buffer, [in] SIZE_T NumberOfBytesToWrite, [out, optional] PSIZE_T NumberOfBytesWritten);
NTSTATUS NTAPI NtReadVirtualMemory([in] HANDLE ProcessHandle, [in] PVOID BaseAddress, [out] PVOID Buffer, [in] SIZE_T NumberOfBytesToRead, [out, optional] PSIZE_T NumberOfBytesRead);
NTSTATUS NTAPI NtFreeVirtualMemory([in] HANDLE ProcessHandle, [in, out] PVOID *BaseAddress, [in, out] PSIZE_T RegionSize, [in] ULONG FreeType);
NTSTATUS NTAPI NtMapViewOfSection([in] HANDLE SectionHandle, [in] HANDLE ProcessHandle, [in, out] PVOID *BaseAddress, [in] ULONG_PTR ZeroBits, [in] SIZE_T CommitSize, [in, out, optional] PLARGE_INTEGER SectionOffset, [in, out] PSIZE_T ViewSize, [in] DWORD InheritDisposition, [in] ULONG AllocationType, [in] ULONG Win32Protect);
NTSTATUS NTAPI NtUnmapViewOfSection([in] HANDLE ProcessHandle, [in] PVOID BaseAddress);

/* ---- modules ---- */
HMODULE WINAPI LoadLibraryA([in] LPCSTR lpLibFileName);
HMODULE WINAPI LoadLibraryW([in] LPCWSTR lpLibFileName);
HMODULE WINAPI LoadLibraryExA([in] LPCSTR lpLibFileName, [in] HANDLE hFile, [in] DWORD dwFlags);
HMODULE WINAPI LoadLibraryExW([in] LPCWSTR lpLibFileName, [in] HANDLE hFile, [in] DWORD dwFlags);
FARPROC WINAPI GetProcAddress([in] HMODULE hModule, [in] LPCSTR lpProcName);
HMODULE WINAPI GetModuleHandleA([in, optional] LPCSTR lpModuleName);
HMODULE WINAPI GetModuleHandleW([in, optional] LPCWSTR lpModuleName);
DWORD WINAPI GetModuleFileNameW([in, optional] HMODULE hModule, [out] LPWSTR lpFilename, [in] DWORD nSize);
DWORD WINAPI GetModuleFileNameA([in, optional] HMODULE hModule, [out] LPSTR lpFilename, [in] DWORD nSize);
NTSTATUS NTAPI LdrLoadDll([in, optional] PWSTR SearchPath, [in, optional] PULONG DllCharacteristics, [in] PUNICODE_STRING DllName, [out] PVOID *DllHandle);
NTSTATUS NTAPI LdrGetProcedureAddress([in] PVOID DllHandle, [in, optional] PANSI_STRING ProcedureName, [in, optional] ULONG ProcedureNumber, [out] PVOID *ProcedureAddress);

/* ---- processes and threads ---- */
BOOL WINAPI CreateProcessA([in, optional] LPCSTR lpApplicationName, [in, out, optional] LPSTR lpCommandLine, [in, optional] LPSECURITY_ATTRIBUTES lpProcessAttributes, [in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes, [in] BOOL bInheritHandles, [in] DWORD dwCreationFlags, [in, optional] LPVOID lpEnvironment, [in, optional] LPCSTR lpCurrentDirectory, [in] LPSTARTUPINFOA lpStartupInfo, [out] LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI CreateProcessW([in, optional] LPCWSTR lpApplicationName, [in, out, optional] LPWSTR lpCommandLine, [in, optional] LPSECURITY_ATTRIBUTES lpProcessAttributes, [in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes, [in] BOOL bInheritHandles, [in] DWORD dwCreationFlags, [in, optional] LPVOID lpEnvironment, [in, optional] LPCWSTR lpCurrentDirectory, [in] LPSTARTUPINFOW lpStartupInfo, [out] LPPROCESS_INFORMATION lpProcessInformation);
HANDLE WINAPI OpenProcess([in] DWORD dwDesiredAccess, [in] BOOL bInheritHandle, [in] DWORD dwProcessId);
HANDLE WINAPI CreateThread([in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes, [in] SIZE_T dwStackSize, [in] LPTHREAD_START_ROUTINE lpStartAddress, [in, optional] LPVOID lpParameter, [in] DWORD dwCreationFlags, [out, optional] LPDWORD lpThreadId);
HANDLE WINAPI CreateRemoteThread([in] HANDLE hProcess, [in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes, [in] SIZE_T dwStackSize, [in] LPTHREAD_START_ROUTINE lpStartAddress, [in, optional] LPVOID lpParameter, [in] DWORD dwCreationFlags, [out, optional] LPDWORD lpThreadId);
DWORD WINAPI ResumeThread([in] HANDLE hThread);
DWORD WINAPI SuspendThread([in] HANDLE hThread);
BOOL WINAPI SetThreadContext([in] HANDLE hThread, [in] const CONTEXT *lpContext);
BOOL WINAPI GetThreadContext([in] HANDLE hThread, [in, out] LPCONTEXT lpContext);
NTSTATUS NTAPI NtCreateThreadEx([out] PHANDLE ThreadHandle, [in] ACCESS_MASK DesiredAccess, [in, optional] POBJECT_ATTRIBUTES ObjectAttributes, [in] HANDLE ProcessHandle, [in] PVOID StartRoutine, [in, optional] PVOID Argument, [in] ULONG CreateFlags, [in] SIZE_T ZeroBits, [in] SIZE_T StackSize, [in] SIZE_T MaximumStackSize, [in, optional] PVOID AttributeList);
NTSTATUS NTAPI NtQueueApcThread([in] HANDLE ThreadHandle, [in] PVOID ApcRoutine, [in, optional] PVOID ApcArgument1, [in, optional] PVOID ApcArgument2, [in, optional] PVOID ApcArgument3);
VOID WINAPI ExitProcess([in] UINT uExitCode);
BOOL WINAPI TerminateProcess([in] HANDLE hProcess, [in] UINT uExitCode);

/* ---- files ---- */
HANDLE WINAPI CreateFileA([in] LPCSTR lpFileName, [in] DWORD dwDesiredAccess, [in] DWORD dwShareMode, [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes, [in] DWORD dwCreationDisposition, [in] DWORD dwFlagsAndAttributes, [in, optional] HANDLE hTemplateFile);
HANDLE WINAPI CreateFileW([in] LPCWSTR lpFileName, [in] DWORD dwDesiredAccess, [in] DWORD dwShareMode, [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes, [in] DWORD dwCreationDisposition, [in] DWORD dwFlagsAndAttributes, [in, optional] HANDLE hTemplateFile);
BOOL WINAPI ReadFile([in] HANDLE hFile, [out] LPVOID lpBuffer, [in] DWORD nNumberOfBytesToRead, [out, optional] LPDWORD lpNumberOfBytesRead, [in, out, optional] LPOVERLAPPED lpOverlapped);
BOOL WINAPI WriteFile([in] HANDLE hFile, [in] LPCVOID lpBuffer, [in] DWORD nNumberOfBytesToWrite, [out, optional] LPDWORD lpNumberOfBytesWritten, [in, out, optional] LPOVERLAPPED lpOverlapped);
BOOL WINAPI DeleteFileW([in] LPCWSTR lpFileName);
BOOL WINAPI DeleteFileA([in] LPCSTR lpFileName);
BOOL WINAPI CopyFileW([in] LPCWSTR lpExistingFileName, [in] LPCWSTR lpNewFileName, [in] BOOL bFailIfExists);
BOOL WINAPI CopyFileA([in] LPCSTR lpExistingFileName, [in] LPCSTR lpNewFileName, [in] BOOL bFailIfExists);
BOOL WINAPI MoveFileExW([in] LPCWSTR lpExistingFileName, [in, optional] LPCWSTR lpNewFileName, [in] DWORD dwFlags);
BOOL WINAPI MoveFileExA([in] LPCSTR lpExistingFileName, [in, optional] LPCSTR lpNewFileName, [in] DWORD dwFlags);
HANDLE WINAPI CreateFileMappingW([in] HANDLE hFile, [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes, [in] DWORD dwProtect, [in] DWORD dwMaximumSizeHigh, [in] DWORD dwMaximumSizeLow, [in, optional] LPCWSTR lpName);
HANDLE WINAPI CreateFileMappingA([in] HANDLE hFile, [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes, [in] DWORD dwProtect, [in] DWORD dwMaximumSizeHigh, [in] DWORD dwMaximumSizeLow, [in, optional] LPCSTR lpName);
LPVOID WINAPI MapViewOfFile([in] HANDLE hFileMappingObject, [in] DWORD dwDesiredAccess, [in] DWORD dwFileOffsetHigh, [in] DWORD dwFileOffsetLow, [in] SIZE_T dwNumberOfBytesToMap);

/* ---- registry ---- */
LSTATUS WINAPI RegOpenKeyExW([in] HKEY hKey, [in, optional] LPCWSTR lpSubKey, [in] DWORD ulOptions, [in] REGSAM samDesired, [out] PHKEY phkResult);
LSTATUS WINAPI RegOpenKeyExA([in] HKEY hKey, [in, optional] LPCSTR lpSubKey, [in] DWORD ulOptions, [in] REGSAM samDesired, [out] PHKEY phkResult);
LSTATUS WINAPI RegSetValueExW([in] HKEY hKey, [in, optional] LPCWSTR lpValueName, [in] DWORD Reserved, [in] DWORD dwType, [in] const BYTE *lpData, [in] DWORD cbData);
LSTATUS WINAPI RegSetValueExA([in] HKEY hKey, [in, optional] LPCSTR lpValueName, [in] DWORD Reserved, [in] DWORD dwType, [in] const BYTE *lpData, [in] DWORD cbData);
LSTATUS WINAPI RegQueryValueExW([in] HKEY hKey, [in, optional] LPCWSTR lpValueName, [in, out, optional] LPDWORD lpReserved, [out, optional] LPDWORD lpType, [out, optional] LPBYTE lpData, [in, out, optional] LPDWORD lpcbData);
LSTATUS WINAPI RegQueryValueExA([in] HKEY hKey, [in, optional] LPCSTR lpValueName, [in, out, optional] LPDWORD lpReserved, [out, optional] LPDWORD lpType, [out, optional] LPBYTE lpData, [in, out, optional] LPDWORD lpcbData);
LSTATUS WINAPI RegCreateKeyExW([in] HKEY hKey, [in] LPCWSTR lpSubKey, [in] DWORD Reserved, [in, optional] LPWSTR lpClass, [in] DWORD dwOptions, [in] REGSAM samDesired, [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes, [out] PHKEY phkResult, [out, optional] LPDWORD lpdwDisposition);
LSTATUS WINAPI RegCreateKeyExA([in] HKEY hKey, [in] LPCSTR lpSubKey, [in] DWORD Reserved, [in, optional] LPSTR lpClass, [in] DWORD dwOptions, [in] REGSAM samDesired, [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes, [out] PHKEY phkResult, [out, optional] LPDWORD lpdwDisposition);

/* ---- network ---- */
HINTERNET WINAPI InternetOpenW([in, optional] LPCWSTR lpszAgent, [in] DWORD dwAccessType, [in, optional] LPCWSTR lpszProxy, [in, optional] LPCWSTR lpszProxyBypass, [in] DWORD dwFlags);
HINTERNET WINAPI InternetOpenA([in, optional] LPCSTR lpszAgent, [in] DWORD dwAccessType, [in, optional] LPCSTR lpszProxy, [in, optional] LPCSTR lpszProxyBypass, [in] DWORD dwFlags);
HINTERNET WINAPI InternetOpenUrlW([in] HINTERNET hInternet, [in] LPCWSTR lpszUrl, [in, optional] LPCWSTR lpszHeaders, [in] DWORD dwHeadersLength, [in] DWORD dwFlags, [in] DWORD_PTR dwContext);
HINTERNET WINAPI InternetOpenUrlA([in] HINTERNET hInternet, [in] LPCSTR lpszUrl, [in, optional] LPCSTR lpszHeaders, [in] DWORD dwHeadersLength, [in] DWORD dwFlags, [in] DWORD_PTR dwContext);
BOOL WINAPI InternetReadFile([in] HINTERNET hFile, [out] LPVOID lpBuffer, [in] DWORD dwNumberOfBytesToRead, [out] LPDWORD lpdwNumberOfBytesRead);
HINTERNET WINAPI HttpOpenRequestW([in] HINTERNET hConnect, [in, optional] LPCWSTR lpszVerb, [in, optional] LPCWSTR lpszObjectName, [in, optional] LPCWSTR lpszVersion, [in, optional] LPCWSTR lpszReferrer, [in, optional] LPCWSTR *lplpszAcceptTypes, [in] DWORD dwFlags, [in] DWORD_PTR dwContext);
HINTERNET WINAPI HttpOpenRequestA([in] HINTERNET hConnect, [in, optional] LPCSTR lpszVerb, [in, optional] LPCSTR lpszObjectName, [in, optional] LPCSTR lpszVersion, [in, optional] LPCSTR lpszReferrer, [in, optional] LPCSTR *lplpszAcceptTypes, [in] DWORD dwFlags, [in] DWORD_PTR dwContext);
int WSAAPI connect([in] SOCKET s, [in] const sockaddr *name, [in] int namelen);
int WSAAPI send([in] SOCKET s, [in] const char *buf, [in] int len, [in] int flags);
int WSAAPI recv([in] SOCKET s, [out] char *buf, [in] int len, [in] int flags);

/* ---- crypto and encoding ---- */
BOOL WINAPI CryptDecrypt([in] HCRYPTKEY hKey, [in] HCRYPTHASH hHash, [in] BOOL Final, [in] DWORD dwFlags, [in, out] BYTE *pbData, [in, out] DWORD *pdwDataLen);
BOOL WINAPI CryptEncrypt([in] HCRYPTKEY hKey, [in] HCRYPTHASH hHash, [in] BOOL Final, [in] DWORD dwFlags, [in, out, optional] BYTE *pbData, [in, out] DWORD *pdwDataLen, [in] DWORD dwBufLen);
BOOL WINAPI CryptStringToBinaryW([in] LPCWSTR pszString, [in] DWORD cchString, [in] DWORD dwFlags, [out] BYTE *pbBinary, [in, out] DWORD *pcbBinary, [out, optional] DWORD *pdwSkip, [out, optional] DWORD *pdwFlags);
BOOL WINAPI CryptStringToBinaryA([in] LPCSTR pszString, [in] DWORD cchString, [in] DWORD dwFlags, [out] BYTE *pbBinary, [in, out] DWORD *pcbBinary, [out, optional] DWORD *pdwSkip, [out, optional] DWORD *pdwFlags);

/* ---- anti-analysis and misc ---- */
BOOL WINAPI IsDebuggerPresent(void);
DWORD WINAPI GetTickCount(void);
DWORD WINAPI GetLastError(void);
VOID WINAPI Sleep([in] DWORD dwMilliseconds);
BOOL WINAPI CheckRemoteDebuggerPresent([in] HANDLE hProcess, [in, out] PBOOL pbDebuggerPresent);
NTSTATUS NTAPI NtQueryInformationProcess([in] HANDLE ProcessHandle, [in] DWORD ProcessInformationClass, [out] PVOID ProcessInformation, [in] ULONG ProcessInformationLength, [out, optional] PULONG ReturnLength);
NTSTATUS NTAPI NtSetInformationThread([in] HANDLE ThreadHandle, [in] DWORD ThreadInformationClass, [in] PVOID ThreadInformation, [in] ULONG ThreadInformationLength);
DWORD WINAPI GetProcessVersion([in] DWORD ProcessId);
BOOL WINAPI GetSystemTimes([out, optional] PFILETIME lpIdleTime, [out, optional] PFILETIME lpKernelTime, [out, optional] PFILETIME lpUserTime);
