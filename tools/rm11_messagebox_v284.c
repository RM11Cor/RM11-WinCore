/*
 * RM11 v2.8.4 - alternate genuine Windows GUI smoke test.
 *
 * Unlike v2.7.8's custom CreateWindow/WM_PAINT implementation, this binary
 * directly calls USER32 MessageBoxW to create a standard Windows modal dialog.
 * Genuine PE32+ x86-64, IMAGE_SUBSYSTEM_WINDOWS_GUI (2), CRT-free.
 *
 * The test is intentionally independent of any game, Steam, internet, Vulkan,
 * XSDL, and a custom window procedure. Auto-closes after ~18 seconds, allowing
 * the Android runner to collect a short log even if no window is visible.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const WCHAR caption[] = L"RM11 Windows MessageBox Test v2.8.4";
static const WCHAR message[] =
    L"Windows USER32 MessageBoxW is running.\n"
    L"If you can SEE this dialog inside RM11,\n"
    L"tap OK now to prove visible interaction.\n"
    L"It closes automatically after 18 seconds.";

static void log_marker(const char *line) {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, written = 0;
    OutputDebugStringA(line);
    while (line[n] != '\0') ++n;
    if (output && output != INVALID_HANDLE_VALUE)
        WriteFile(output, line, n, &written, NULL);
}

static DWORD WINAPI close_after_limit(void *context) {
    HWND dialog = NULL;
    DWORD i;
    (void)context;
    for (i = 0; i < 20; ++i) {
        Sleep(250);
        dialog = FindWindowW(L"#32770", caption);
        if (dialog) break;
    }
    if (dialog) {
        log_marker("RM11_V284_STANDARD_WIN32_DIALOG_HANDLE_FOUND\r\n");
        log_marker("RM11_EXTERNAL_GUI_WINDOW_CREATED\r\n");
        Sleep(18000);
        PostMessageW(dialog, WM_CLOSE, 0, 0);
        log_marker("RM11_V284_DIALOG_AUTO_CLOSE_REQUESTED\r\n");
    } else {
        log_marker("RM11_V284_DIALOG_WINDOW_NOT_FOUND_5S\r\n");
    }
    return 0;
}

void mainCRTStartup(void) {
    HANDLE closer;
    int answer;
    log_marker("RM11_V284_STANDARD_MESSAGEBOX_TEST_STARTED\r\n");
    closer = CreateThread(NULL, 0, close_after_limit, NULL, 0, NULL);
    if (!closer) {
        log_marker("RM11_V284_CLOSER_THREAD_FAILED\r\n");
        ExitProcess(68);
    }
    log_marker("RM11_V284_MESSAGEBOXW_CALL_BEGIN\r\n");
    answer = MessageBoxW(NULL, message, caption,
                         MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    log_marker("RM11_V284_MESSAGEBOXW_RETURNED\r\n");
    if (answer == IDOK)
        log_marker("RM11_V284_OK_PRESSED_OR_DIALOG_ACCEPTED\r\n");
    else if (answer == IDCANCEL)
        log_marker("RM11_V284_DIALOG_CANCELLED_OR_AUTOCLOSED\r\n");
    else if (!answer)
        log_marker("RM11_V284_MESSAGEBOXW_RETURNED_ERROR\r\n");
    CloseHandle(closer);
    ExitProcess(answer ? 48 : 69);
}
