/*
 * RM11 v2.7.1 independent Win64 GUI API diagnostic.
 * Tests Windows USER32 window creation and GDI32 basic drawing; does not
 * imply a visible Android window, functional X11/Wayland, or game rendering.
 * No file writes, network, background work or additional DLL dependencies
 * beyond Windows system USER32/GDI32/KERNEL32.
 */
#include <windows.h>

static LRESULT CALLBACK window_proc(HWND window, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_CLOSE) {
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window,msg,w,l);
}

static void message(const char *s) {
    HANDLE out=GetStdHandle(STD_OUTPUT_HANDLE);
    if(out==NULL || out==INVALID_HANDLE_VALUE)return;
    DWORD length=0;
    while(s[length])length++;
    DWORD written=0;
    WriteFile(out,s,length,&written,NULL);
}

void mainCRTStartup(void) {
    HINSTANCE instance=GetModuleHandleW(NULL);
    WNDCLASSW type={0};
    type.lpfnWndProc=window_proc;
    type.hInstance=instance;
    type.lpszClassName=L"RM11Win64GraphicsPilot";
    if(!RegisterClassW(&type)) {
        message("RM11_GUI_REGISTERCLASS_FAILED\r\n");
        ExitProcess(61);
    }
    HWND win=CreateWindowExW(0,type.lpszClassName,L"RM11 GUI Pilot",
                             WS_OVERLAPPEDWINDOW,120,120,400,240,
                             NULL,NULL,instance,NULL);
    if(!win) {
        message("RM11_GUI_CREATEWINDOW_FAILED\r\n");
        ExitProcess(62);
    }
    ShowWindow(win,SW_SHOWNORMAL);
    UpdateWindow(win);
    HDC dc=GetDC(win);
    if(!dc) {
        message("RM11_GUI_GETDC_FAILED\r\n");
        DestroyWindow(win);
        ExitProcess(63);
    }
    (void)Rectangle(dc,12,12,320,160);
    ReleaseDC(win,dc);
    message("RM11_EXTERNAL_GUI_WINDOW_CREATED\r\n");
    DestroyWindow(win);
    ExitProcess(48);
}
