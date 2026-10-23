/*
 * RM11 v2.8.9: standalone safe allocator preflight for native Wine GDI table.
 *
 * The observed PEB->GdiSharedHandleTable is NULL at startup on REDMAGIC 11 Pro.
 * Wine 11 win32u/gdiobj.c initializes a 65536-entry GDI_SHARED_MEMORY array
 * via NtAllocateVirtualMemory(GetCurrentProcess(),..., zero_bits,...).
 *
 * Unlike the earlier GUI samples, this intentionally DOES NOT use GDI/USER32
 * window operations. It checks whether two non-persistent private allocations
 * of 0x180000 bytes (sizeof 65536 * 24-byte GDI_HANDLE_ENTRY) are supported:
 * unconstrained ZeroBits=0, and constrained ZeroBits=0x7fffffff.
 *
 * The results distinguish availability of low memory from invocation of the
 * actual win32u init callback; they DO NOT themselves repair the PEB.
 *
 * No data or registry writes, no root, no DRM bypass, no EXE dependencies
 * outside Windows system DLLs. Does not display a Windows dialog.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

typedef LONG NT_STATUS;
typedef NT_STATUS (WINAPI *ALLOCATE_T)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NT_STATUS (WINAPI *FREE_T)(HANDLE,PVOID*,PSIZE_T,ULONG);

enum { RM11_GDI_BYTES = 0x180000 };
static void marker(const char *s) {
    HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n=0,done=0;
    while(s[n])n++;
    if(h && h!=INVALID_HANDLE_VALUE)WriteFile(h,s,n,&done,NULL);
}
static void hexstatus(const char *key, unsigned long status) {
    char out[100];
    unsigned i=0,k=0;
    static const char *hex="0123456789ABCDEF";
    while(key[k]&&i<52)out[i++]=key[k++];
    out[i++]='0';out[i++]='x';
    for (k=0;k<8;k++)out[i++]=hex[(status >> ((7-k)*4)) & 15];
    out[i++]='\n';out[i]=0;
    marker(out);
}
static int try_alloc(ALLOCATE_T alloc, FREE_T release, ULONG_PTR zero_bits,
                     const char *label) {
    PVOID address=NULL;
    SIZE_T size=RM11_GDI_BYTES;
    NT_STATUS status=alloc(GetCurrentProcess(),&address,zero_bits,&size,
                           MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    hexstatus(label,(unsigned long)status);
    if(status < 0 || address==NULL) {
        marker("RM11_V289_NTALLOC_FAILED\n");
        return 0;
    }
    marker("RM11_V289_NTALLOC_SUCCESS\n");
    if(release) {
        SIZE_T zero=0;
        NT_STATUS rs=release(GetCurrentProcess(),&address,&zero,MEM_RELEASE);
        if(rs<0)hexstatus("RM11_V289_NTFREE_FAILED=", (unsigned long)rs);
        else marker("RM11_V289_ALLOCATION_RELEASED\n");
    }
    return 1;
}
void mainCRTStartup(void) {
    ULONG_PTR peb=(ULONG_PTR)__readgsqword(0x60);
    const volatile ULONG_PTR *gdiptr;
    HMODULE ntdll;
    ALLOCATE_T allocate;
    FREE_T release;
    int unrestricted,low;

    marker("RM11_V289_EXE_ENTRY\n");
    if(!peb) {
        marker("RM11_V289_PEB_MISSING\n");
        ExitProcess(91);
    }
    gdiptr=(const volatile ULONG_PTR *)(peb+0xf8);
    marker(*gdiptr==0 ? "RM11_V289_GDI_TABLE_BEFORE_NULL\n" :
                         "RM11_V289_GDI_TABLE_BEFORE_NON_NULL\n");

    ntdll=GetModuleHandleW(L"ntdll.dll");
    if(!ntdll) {
        marker("RM11_V289_NTDLL_NOT_LOADED\n");
        ExitProcess(92);
    }
    allocate=(ALLOCATE_T)(void*)GetProcAddress(ntdll,"NtAllocateVirtualMemory");
    release=(FREE_T)(void*)GetProcAddress(ntdll,"NtFreeVirtualMemory");
    if(!allocate || !release) {
        marker("RM11_V289_NTDLL_ALLOCATOR_EXPORTS_NOT_FOUND\n");
        ExitProcess(93);
    }
    marker("RM11_V289_NTDLL_ALLOCATOR_EXPORTS_FOUND\n");

    unrestricted=try_alloc(allocate,release,0,
             "RM11_V289_NTALLOC_ZEROBITS_0_STATUS=");
    low=try_alloc(allocate,release,0x7fffffff,
             "RM11_V289_NTALLOC_LOW_ADDRESS_STATUS=");

    marker(*gdiptr==0 ? "RM11_V289_GDI_TABLE_AFTER_NULL\n" :
                         "RM11_V289_GDI_TABLE_AFTER_NON_NULL\n");

    if(unrestricted && low) {
        marker("RM11_V289_BOTH_ALLOCATIONS_SUCCEEDED\n");
        marker("RM11_V289_IF_TABLE_NULL_INIT_CALLBACK_NOT_PROVEN\n");
        ExitProcess(88);
    }
    if(unrestricted && !low) {
        marker("RM11_V289_LOW_ADDRESS_CONSTRAINT_FAILED_WHILE_UNRESTRICTED_SUCCEEDED\n");
        ExitProcess(87);
    }
    if(!unrestricted && !low) {
        marker("RM11_V289_BOTH_ALLOCATIONS_FAILED\n");
        ExitProcess(86);
    }
    marker("RM11_V289_ONLY_LOW_ALLOCATION_SUCCEEDED\n");
    ExitProcess(89);
}
