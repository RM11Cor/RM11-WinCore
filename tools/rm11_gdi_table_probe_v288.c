/*
 * RM11 v2.8.8 - x86-64 Windows PE in-process GDI shared handle table probe.
 *
 * Diagnostic of real Wine PEB memory. No root, injection, ptrace, registry
 * writes, game files, or Wine DLL patches. If the GDI table is null,
 * STOP before using GDI/MessageBox to avoid a known 0x2AE page fault.
 *
 * Evidence: ARM64 Wine gdi32.dll RVA 0x772D4:
 *  ldr x9, [x18,#0x60]; ldr x9, [x9,#0xF8]; ... ldrb [x9,#0xE]
 * Reads PEB->GdiSharedHandleTable.  x64 Wine TEB via GS:0x60.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#define DIAG_GDI_SHARED_PEB_OFFSET 0xF8

static const WCHAR title[] = L"RM11 GDI Shared Table Test v2.8.8";
static const WCHAR message[] =
    L"Wine GDI shared handle table is present.\n"
    L"If this STANDARD Windows window is visible,\n"
    L"tap OK and send the new RM11 diagnostics.";
static volatile LONG did_close;

static void report(const char *line) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n=0, written=0;
    OutputDebugStringA(line);
    while (line[n]) n++;
    if (out && out!=INVALID_HANDLE_VALUE) WriteFile(out,line,n,&written,NULL);
}

static int isReadablePebSlot(const void *slot) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T queried = VirtualQuery(slot,&mbi,sizeof(mbi));
    if (queried != sizeof(mbi)) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) return 0;
    return 1;
}

static DWORD WINAPI boundedDialogCloser(LPVOID unused) {
    HWND hwnd = NULL;
    DWORD n;
    (void)unused;
    for (n=0;n<64;n++) {
        if (did_close) break;
        hwnd = FindWindowW(L"#32770",title);
        if (hwnd) break;
        Sleep(250);
    }
    if (hwnd && !did_close) {
        report("RM11_GDI_V288_DIALOG_HANDLE_SEEN\n");
        Sleep(14000);
        if (!did_close) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            report("RM11_GDI_V288_AUTO_CLOSE_REQUESTED\n");
        }
    } else {
        report("RM11_GDI_V288_DIALOG_WINDOW_NOT_OBSERVED\n");
    }
    return 0;
}

void mainCRTStartup(void) {
    ULONG_PTR peb, shared;
    const void *slot;
    HANDLE closer;
    int result;

    report("RM11_GDI_V288_ENTRY_REACHED\n");
    report("RM11_GDI_V288_STATIC_USER32_IMPORTED\n");

    /* GS:0x60 is the x86-64 TEB's PEB pointer under Windows/Wine. */
    peb=(ULONG_PTR)__readgsqword(0x60);
    if (!peb) {
        report("RM11_GDI_V288_PEB_NULL\n");
        ExitProcess(71);
    }
    report("RM11_GDI_V288_PEB_NON_NULL\n");

    slot=(const void *)(peb + DIAG_GDI_SHARED_PEB_OFFSET);
    if (!isReadablePebSlot(slot)) {
        report("RM11_GDI_V288_PEB_GDI_SLOT_NOT_READABLE\n");
        ExitProcess(73);
    }

    shared=*(const volatile ULONG_PTR *)slot;
    if (!shared) {
        report("RM11_GDI_V288_GDI_SHARED_HANDLE_TABLE_NULL\n");
        report("RM11_GDI_V288_STOPPED_BEFORE_UNSAFE_GDI_ACCESS\n");
        ExitProcess(72);
    }
    report("RM11_GDI_V288_GDI_SHARED_HANDLE_TABLE_NON_NULL\n");
    if (!isReadablePebSlot((const void*)shared)) {
        report("RM11_GDI_V288_GDI_SHARED_HANDLE_TABLE_UNREADABLE\n");
        ExitProcess(74);
    }
    report("RM11_GDI_V288_GDI_SHARED_HANDLE_TABLE_READABLE\n");
    report("RM11_GDI_V288_MESSAGEBOXW_BEGIN\n");
    closer=CreateThread(NULL,0,boundedDialogCloser,NULL,0,NULL);
    if (!closer) {
        report("RM11_GDI_V288_CLOSER_CREATION_FAILED\n");
        ExitProcess(75);
    }
    result=MessageBoxW(NULL,message,title,MB_OK|MB_ICONINFORMATION|MB_SETFOREGROUND);
    InterlockedExchange(&did_close,1);
    report("RM11_GDI_V288_MESSAGEBOXW_RETURNED\n");
    if (result==IDOK) report("RM11_GDI_V288_MESSAGEBOXW_OK\n");
    CloseHandle(closer);
    ExitProcess(result?48:76);
}
