/*
 * RM11 v2.9.0 - Cross-architecture Wine PEB / loader environment diagnostic.
 *
 * Safely compare x64 GS TEB->PEB and Wine NtQueryInformationProcess PEB
 * before/after USER32 LoadLibraryW, inspect public WIN32U initializer export,
 * and test whether Windows process receives WINEDATADIR from Android.
 *
 * Do not call private initialization APIs or modify Wine state/data/PEB.
 * Does not use MessageBox, create a GUI window or allocate GDI tables.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

typedef LONG NTSTATUS_LOCAL;
typedef NTSTATUS_LOCAL (WINAPI *NT_QUERY_PROCESS)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct _RM11_BASIC_INFO {
    NTSTATUS_LOCAL exitStatus;
    PVOID pebBase;
    ULONG_PTR affinityMask;
    LONG basePriority;
    ULONG_PTR pid;
    ULONG_PTR inheritedPid;
} RM11_BASIC_INFO;

static void marker(const char *s) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n=0,done=0;
    OutputDebugStringA(s);
    while(s[n])n++;
    if(out && out!=INVALID_HANDLE_VALUE) WriteFile(out,s,n,&done,NULL);
}
static void reporthex(const char *name, ULONG_PTR value) {
    char out[112];
    static const char h[]="0123456789ABCDEF";
    unsigned a=0,j=0;
    while(name[j] && a<69) out[a++]=name[j++];
    out[a++]='0';out[a++]='x';
    for(j=0;j<sizeof(ULONG_PTR)*2;j++){
        unsigned shift=((unsigned)sizeof(ULONG_PTR)*2-1-j)*4;
        out[a++]=h[(value>>shift)&15];
    }
    out[a++]='\n';out[a]=0;
    marker(out);
}
static int readable(const void *p) {
    MEMORY_BASIC_INFORMATION m;
    SIZE_T got;
    if (!p) return 0;
    got=VirtualQuery(p,&m,sizeof(m));
    if (got!=sizeof(m) || m.State!=MEM_COMMIT) return 0;
    if(m.Protect & (PAGE_NOACCESS|PAGE_GUARD)) return 0;
    return 1;
}
static ULONG_PTR gdiSlot(ULONG_PTR peb) {
    const void *slot = (const void *)(peb+0xf8);
    if(!peb || !readable(slot)) return 0;
    return *(const volatile ULONG_PTR *)slot;
}
static void envStat(const WCHAR *name,const char *found,const char *missing) {
    WCHAR buf[1024];
    DWORD n=GetEnvironmentVariableW(name,buf,1024);
    marker(n>0 && n<1024 ? found : missing);
}
void mainCRTStartup(void) {
    HMODULE ntdll,win32u,user32;
    NT_QUERY_PROCESS ntquery;
    RM11_BASIC_INFO bi={0};
    ULONG_PTR gspeb=(ULONG_PTR)__readgsqword(0x60), ntpeb=0;
    ULONG retlen=0;
    NTSTATUS_LOCAL status;

    marker("RM11_V290_ENTRY_REACHED\n");
    envStat(L"WINEDATADIR","RM11_V290_WINEDATADIR_WINDOWS_ENV_PRESENT\n",
                          "RM11_V290_WINEDATADIR_WINDOWS_ENV_ABSENT\n");
    envStat(L"WINEBUILDDIR","RM11_V290_WINEBUILDDIR_WINDOWS_ENV_PRESENT\n",
                           "RM11_V290_WINEBUILDDIR_WINDOWS_ENV_ABSENT\n");
    ntdll=GetModuleHandleW(L"ntdll.dll");
    if(!ntdll) {
        marker("RM11_V290_NTDLL_MODULE_NOT_FOUND\n");
        ExitProcess(95);
    }
    ntquery=(NT_QUERY_PROCESS)(void*)GetProcAddress(ntdll,"NtQueryInformationProcess");
    if(!ntquery) {
        marker("RM11_V290_NTQUERY_EXPORT_NOT_FOUND\n");
        ExitProcess(96);
    }
    status=ntquery(GetCurrentProcess(),0,&bi,sizeof(bi),&retlen);
    reporthex("RM11_V290_NTQUERY_STATUS=",(ULONG_PTR)(unsigned long)status);
    if(status >= 0) ntpeb=(ULONG_PTR)bi.pebBase;
    reporthex("RM11_V290_X64_GS_PEB=",gspeb);
    reporthex("RM11_V290_NTQUERY_PEB=",ntpeb);
    if(!ntpeb || !gspeb) {
        marker("RM11_V290_PEB_UNAVAILABLE_NO_UNSAFE_READ\n");
        ExitProcess(97);
    }
    marker(ntpeb==gspeb
         ? "RM11_V290_PEB_IDENTITY_MATCH\n"
         : "RM11_V290_PEB_IDENTITY_MISMATCH\n");
    reporthex("RM11_V290_X64_GDI_TABLE_BEFORE=",gdiSlot(gspeb));
    reporthex("RM11_V290_NTQUERY_GDI_TABLE_BEFORE=",gdiSlot(ntpeb));

    user32=LoadLibraryW(L"user32.dll");
    if(!user32) {
        marker("RM11_V290_USER32_LOAD_FAILED\n");
        ExitProcess(98);
    }
    marker("RM11_V290_USER32_LOAD_SUCCEEDED\n");
    win32u=GetModuleHandleW(L"win32u.dll");
    if(!win32u) {
        marker("RM11_V290_WIN32U_NOT_PRELOADED\n");
        win32u=LoadLibraryW(L"win32u.dll");
    }
    if(win32u) {
        marker("RM11_V290_WIN32U_LOADED\n");
        if(GetProcAddress(win32u,"NtUserInitializeClientPfnArrays"))
            marker("RM11_V290_NTUSER_INIT_EXPORT_RESOLVED\n");
        else marker("RM11_V290_NTUSER_INIT_EXPORT_UNAVAILABLE\n");
    } else marker("RM11_V290_WIN32U_LOAD_FAILED\n");

    reporthex("RM11_V290_X64_GDI_TABLE_AFTER=",gdiSlot(gspeb));
    reporthex("RM11_V290_NTQUERY_GDI_TABLE_AFTER=",gdiSlot(ntpeb));
    marker("RM11_V290_READONLY_GDI_PEB_CHECK_COMPLETE\n");
    marker("RM11_V290_NO_GDI_INIT_CALLED_OR_PATCHED\n");
    ExitProcess(90);
}
