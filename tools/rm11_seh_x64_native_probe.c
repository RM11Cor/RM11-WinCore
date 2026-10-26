/* RM11 v4.0.60: independent, bundled x86-64 Windows exception/unwind probe.
 * No game files, registry writes, graphical dependencies, internet or copying.
 * Win64 SEH (__try/__except) is tested through Wine ARM64EC/FEX.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#define RM11_SEH_TEST_EXCEPTION ((DWORD)0xe0420600u)

static void line(const char *str) {
    HANDLE console=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n=0;
    DWORD len=lstrlenA(str);
    if(console!=INVALID_HANDLE_VALUE && console!=NULL)
        WriteFile(console,str,len,&n,NULL);
}

__declspec(noinline) static int nested_frame(volatile LONG *result) {
    __try {
        RaiseException(RM11_SEH_TEST_EXCEPTION,0,0,NULL);
        *result=-999;
    } __except (GetExceptionCode()==RM11_SEH_TEST_EXCEPTION
                    ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        *result=60;
        line("RM11_V460_SEH_HANDLER_REACHED=YES\n");
    }
    return (int)*result;
}

int main(void) {
    volatile LONG result=0;
    line("RM11_V460_SEH_PROBE_STARTED=x64\n");
    int n=nested_frame(&result);
    if(n!=60) {
        line("RM11_V460_SEH_PROBE_FAILED=HANDLER_NOT_EXECUTED\n");
        return 61;
    }
    line("RM11_V460_SEH_PROBE_PASS=YES\n");
    return 0;
}
