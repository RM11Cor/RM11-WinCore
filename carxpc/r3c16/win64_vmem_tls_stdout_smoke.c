/*
 * CarX PC Runtime R3C16 — minimal actual Win64 PE API boundary fixture.
 * This is a fresh open-source diagnostic program, NOT CarX Street.exe.
 * Native Linux/Android executables must never be mistaken for this PE64.
 */
#include <windows.h>
#include <stdint.h>
#include <string.h>

static int fail(int code) { return code; }

int main(void) {
    /* Distinct Windows API groups needed beyond the original GNU ELF sample:
       process/thread identity; guest virtual memory; Windows TLS;
       4KiB protection round-trip; Windows stdout handle. */
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    if (!pid || !tid) return fail(11);

    LPVOID memory=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!memory) return fail(12);
    volatile uint8_t *p=(volatile uint8_t *)memory;
    for (DWORD i=0;i<4096;i++) p[i]=(uint8_t)((i*17u+3u)&255u);
    for (DWORD i=0;i<4096;i++)
        if(p[i]!=(uint8_t)((i*17u+3u)&255u))return fail(13);

    DWORD slot=TlsAlloc();
    if(slot==TLS_OUT_OF_INDEXES) return fail(14);
    if(!TlsSetValue(slot,memory)) return fail(15);
    if(TlsGetValue(slot)!=memory) return fail(16);
    if(!TlsFree(slot)) return fail(17);

    DWORD oldProtect=0,restored=0;
    if(!VirtualProtect(memory,4096,PAGE_READONLY,&oldProtect))return fail(18);
    if(!VirtualProtect(memory,4096,oldProtect,&restored))return fail(19);
    if(restored!=PAGE_READONLY)return fail(20);
    if(!VirtualFree(memory,0,MEM_RELEASE))return fail(21);

    static const char marker[]="CARX_R3C16_REAL_WIN64_PE_WINAPI_VMEM_TLS_STDOUT_PASS\r\n";
    HANDLE out=GetStdHandle(STD_OUTPUT_HANDLE);
    if(out==NULL || out==INVALID_HANDLE_VALUE)return fail(22);
    DWORD written=0;
    if(!WriteFile(out,marker,(DWORD)(sizeof(marker)-1u),&written,NULL))return fail(23);
    if(written!=sizeof(marker)-1u)return fail(24);
    return 0;
}
