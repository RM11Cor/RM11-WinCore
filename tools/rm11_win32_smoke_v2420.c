/* Actual Windows PE32+ console program compiled for x86-64.
   No external games, Steam or Windows files are used. */
#include <windows.h>
void mainCRTStartup(void) {
    static const char message[] = "RM11_WIN32_EXE_EXECUTED_OK\r\n";
    DWORD count = 0;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output != INVALID_HANDLE_VALUE && output != NULL) {
        WriteFile(output, message, sizeof(message)-1, &count, NULL);
    }
    ExitProcess(42);
}
