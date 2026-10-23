/*
 * RM11 v2.7.8: independent 64-bit Windows GUI visibility / interaction probe.
 * Display a real USER32 top-level window for 25 seconds, dispatch GDI32 WM_PAINT,
 * report real touch/clicks, close cleanly. No CRT, no filesystem/network activity,
 * no privileged access, and no Windows/game authentication bypass.
 *
 * Only visible XServer display + actual user interaction proves GUI rendering;
 * API calls or exit code alone do not.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HWND g_window;
static int g_clicked;

static void log_message(const char *text) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out == NULL || out == INVALID_HANDLE_VALUE) return;
    DWORD length = 0, written = 0;
    while (text[length] != 0) length++;
    WriteFile(out, text, length, &written, NULL);
}

static LRESULT CALLBACK window_proc(HWND window, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT paint;
            HDC dc = BeginPaint(window, &paint);
            if (!dc) return 0;
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(30, 95, 185));
            Rectangle(dc, 12, 12, 390, 200);
            const WCHAR title[] = L"RM11-WinCore 2.7.8 - X11 GUI";
            TextOutW(dc, 28, 36, title, (int)(sizeof(title) / sizeof(title[0]) - 1));
            const WCHAR instructions[] = L"Tap this window to verify input.";
            TextOutW(dc, 28, 90, instructions, (int)(sizeof(instructions) / sizeof(instructions[0]) - 1));
            if (g_clicked) {
                SetTextColor(dc, RGB(0, 130, 70));
                const WCHAR passed[] = L"TOUCH RECEIVED";
                TextOutW(dc, 28, 145, passed, (int)(sizeof(passed) / sizeof(passed[0]) - 1));
            }
            EndPaint(window, &paint);
            log_message("RM11_GUI_V278_GDI_PAINT_CALLED\r\n");
            return 0;
        }
        case WM_LBUTTONDOWN:
            g_clicked = 1;
            log_message("RM11_GUI_V278_TOUCH_RECEIVED\r\n");
            InvalidateRect(window, NULL, TRUE);
            return 0;
        case WM_TIMER:
            if (w == 1) {
                log_message("RM11_GUI_V278_TIMER_ELAPSED\r\n");
                DestroyWindow(window);
            }
            return 0;
        case WM_CLOSE:
            log_message("RM11_GUI_V278_USER_CLOSED\r\n");
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, msg, w, l);
    }
}

void mainCRTStartup(void) {
    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.lpszClassName = L"RM11V278WindowHoldProbe";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (!RegisterClassW(&wc)) {
        log_message("RM11_GUI_V278_REGISTERCLASS_FAILED\r\n");
        ExitProcess(61);
    }
    g_window = CreateWindowExW(0, wc.lpszClassName, L"RM11 Windows GUI - X11 test",
              WS_OVERLAPPEDWINDOW | WS_VISIBLE, 20, 20, 450, 260,
              NULL, NULL, instance, NULL);
    if (!g_window) {
        log_message("RM11_GUI_V278_CREATEWINDOW_FAILED\r\n");
        ExitProcess(62);
    }
    ShowWindow(g_window, SW_SHOW);
    UpdateWindow(g_window);
    log_message("RM11_EXTERNAL_GUI_WINDOW_CREATED\r\n");
    log_message("RM11_GUI_V278_HOLD_25_SECONDS\r\n");
    if (!SetTimer(g_window, 1, 25000, NULL)) {
        log_message("RM11_GUI_V278_SETTIMER_FAILED\r\n");
        DestroyWindow(g_window);
        ExitProcess(63);
    }
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(g_window, 1);
    log_message(g_clicked ? "RM11_GUI_V278_VISIBLE_USER_TOUCH_PROBE_COMPLETE\r\n"
                          : "RM11_GUI_V278_EXITED_WITHOUT_TOUCH\r\n");
    ExitProcess(48);
}
