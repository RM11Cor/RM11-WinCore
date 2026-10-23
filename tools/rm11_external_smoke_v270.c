/* Separate, reproducibly built user-selected Windows x86-64 console EXE.
 * Distinct from bundled rm11-win32-smoke-v2420.exe.
 * No filesystem writes, network calls, spawning, game dependencies or CRT.
 */
#include <windows.h>

void mainCRTStartup(void) {
    static const char message[]="RM11_EXTERNAL_EXE_TEST_OK\r\n";
    DWORD written=0;
    HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
    if(output!=INVALID_HANDLE_VALUE && output!=NULL)
        WriteFile(output,message,(DWORD)(sizeof(message)-1),&written,NULL);
    ExitProcess(47);
}
