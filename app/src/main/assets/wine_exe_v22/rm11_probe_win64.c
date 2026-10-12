/* RM11 V2.2: independent Win64 executable; Win32 APIs, no CRT or external game.
 * A successful probe must create a fresh marker file through Wine and exit 0.
 * This source targets Windows x86-64 PE, NOT an Android/Linux ELF.
 */
#ifdef __clang__
#define DLLIMPORT __declspec(dllimport)
#else
#define DLLIMPORT __attribute__((dllimport))
#endif
#define WINAPI __stdcall
#define GENERIC_WRITE 0x40000000u
#define CREATE_ALWAYS 2u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define INVALID_HANDLE_VALUE ((void *)-1)
typedef void* HANDLE;
typedef unsigned long DWORD; /* Win32 unsigned long is 32 bits in MSVC target */
DLLIMPORT HANDLE WINAPI CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
DLLIMPORT int WINAPI WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
DLLIMPORT int WINAPI CloseHandle(HANDLE);
DLLIMPORT void WINAPI ExitProcess(DWORD);

void WINAPI mainCRTStartup(void) {
    const char path[] = "RM11-V22-WIN32-OK.txt";
    const char data[] = "RM11_V22_WINDOWS_PE_EXEC_OK\n";
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, (void*)0, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, (HANDLE)0);
    if (h == INVALID_HANDLE_VALUE || h == (HANDLE)0) ExitProcess(21);
    DWORD count = 0;
    int success = WriteFile(h, data, sizeof(data) - 1, &count, (void*)0);
    CloseHandle(h);
    if (!success || count != sizeof(data) - 1) ExitProcess(22);
    ExitProcess(0);
}
