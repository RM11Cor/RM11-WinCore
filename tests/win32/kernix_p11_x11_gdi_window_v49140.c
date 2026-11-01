/* Signed-source Win64 GDI/X11 window probe for isolated Proton + FEX.
 * No DirectX, Vulkan, game files, desktop shell or network access.
 * It creates a real Win32 HWND, paints a magenta region then cyan,
 * and exits by itself after twelve seconds. This is only a GUI-path probe.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
static DWORD start_tick;
static int painted;
static int magenta_painted;
static int cyan_painted;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    (void)wp; (void)lp;
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc=BeginPaint(hwnd,&ps);
        if (!dc) return 0;
        RECT area;
        GetClientRect(hwnd,&area);
        DWORD elapsed=GetTickCount()-start_tick;
        const int cyan=(elapsed>=5500u);
        HBRUSH background=CreateSolidBrush(cyan?RGB(0,224,235):RGB(242,25,153));
        if (background) {
            FillRect(dc,&area,background);
            DeleteObject(background);
        }
        EndPaint(hwnd,&ps);
        ++painted;
        if (!cyan&&!magenta_painted) {
            magenta_painted=1;
            puts("P11_GDI_STAGE_MAGENTA_PAINT");
            puts("KERNIX_P11_X11_GDI_MAGENTA_PAINTED");
            fflush(stdout);
        }
        if (cyan&&!cyan_painted) {
            cyan_painted=1;
            puts("P11_GDI_STAGE_CYAN_PAINT");
            puts("KERNIX_P11_X11_GDI_CYAN_PAINTED");
            fflush(stdout);
        }
        return 0;
    }
    case WM_TIMER:
        if (GetTickCount()-start_tick >= 12000u) {
            KillTimer(hwnd,1);
            DestroyWindow(hwnd);
        } else InvalidateRect(hwnd,NULL,FALSE);
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd,message,wp,lp);
    }
}
int main(void) {
    puts("P11_GDI_STAGE_MAIN_ENTER");
    fflush(stdout);
    HINSTANCE instance=GetModuleHandleW(NULL);
    WNDCLASSW cls={0};
    cls.lpfnWndProc=wndproc;
    cls.hInstance=instance;
    cls.lpszClassName=L"KERNIX_P11_SIGNED_GDI_WINDOW";
    cls.hCursor=LoadCursorW(NULL,MAKEINTRESOURCEW(32512));
    puts("P11_GDI_STAGE_REGISTER_ENTER");
    fflush(stdout);
    if (!RegisterClassW(&cls)) {
        printf("KERNIX_P11_X11_REGISTER_FAILED=%lu\n",(unsigned long)GetLastError());
        return 40;
    }
    puts("P11_GDI_STAGE_REGISTER_SUCCESS");
    fflush(stdout);
    start_tick=GetTickCount();
    puts("P11_GDI_STAGE_CREATE_ENTER");
    fflush(stdout);
    HWND hwnd=CreateWindowExW(0,cls.lpszClassName,L"KERNIX Proton 11 X11 window",
        WS_OVERLAPPEDWINDOW|WS_VISIBLE,
        160,90,960,540,NULL,NULL,instance,NULL);
    if (!hwnd) {
        printf("KERNIX_P11_X11_CREATE_FAILED=%lu\n",(unsigned long)GetLastError());
        return 41;
    }
    puts("P11_GDI_STAGE_CREATE_SUCCESS");
    puts("KERNIX_P11_X11_GDI_WINDOW_CREATED");
    fflush(stdout);
    ShowWindow(hwnd,SW_SHOW);
    UpdateWindow(hwnd);
    if (!SetTimer(hwnd,1,250,NULL)) {
        puts("KERNIX_P11_X11_TIMER_FAILED");
        DestroyWindow(hwnd);
        return 42;
    }
    MSG msg;
    while (GetMessageW(&msg,NULL,0,0)>0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    printf("KERNIX_P11_X11_GDI_PAINT_COUNT=%d\n",painted);
    printf("KERNIX_P11_X11_GDI_BOTH_COLORS=%d\n",
        magenta_painted&&cyan_painted);
    fflush(stdout);
    return painted>0 && magenta_painted&&cyan_painted ? 48 : 43;
}
