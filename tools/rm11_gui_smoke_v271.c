/* RM11 v2.7.1: Independent Win64 GUI/display preflight.
 * 
 * Use the existing v2.7.0 Android external-EXE picker. No dependencies,
 * filesystem modifications, networking, child processes or CRT. This does NOT
 * provide an Android graphics backend; it tests whether Wine has one ready.
 *
 * Exit codes: 71=user32 missing, 72=gdi32 missing, 73=Win32 UI export missing,
 * 74=window class registration failed, 75=CreateWindowExW failed,
 * 76=window API created a window (not proof of a displayed frame).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef ATOM (WINAPI *REG_CLASS)(const WNDCLASSW *);
typedef HWND (WINAPI *CREATE_WINDOW)(DWORD,LPCWSTR,LPCWSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
typedef LRESULT (WINAPI *DEF_PROC)(HWND,UINT,WPARAM,LPARAM);
typedef BOOL (WINAPI *SHOW_WINDOW)(HWND,int);
typedef BOOL (WINAPI *UPDATE_WINDOW)(HWND);
typedef BOOL (WINAPI *DESTROY_WINDOW)(HWND);
typedef HDC (WINAPI *GET_DC)(HWND);
typedef int (WINAPI *RELEASE_DC)(HWND,HDC);
typedef int (WINAPI *GET_CAPS)(HDC,int);
static DEF_PROC g_def_window_proc;

static void write_line(const char *s) {
    HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
    if (output==NULL || output==INVALID_HANDLE_VALUE) return;
    DWORD n=0;
    const char *p=s;
    while(*p) ++p;
    (void)WriteFile(output,s,(DWORD)(p-s),&n,NULL);
}
static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    return g_def_window_proc ? g_def_window_proc(hwnd,msg,wparam,lparam) : 0;
}
static void finish(const char *marker, DWORD code) {
    write_line(marker);
    ExitProcess(code);
}

void mainCRTStartup(void) {
    static const WCHAR klass[] = L"RM11GUIProbeWindowV271";
    static const WCHAR windowTitle[] = L"RM11-WinCore GUI capability diagnostic";
    write_line("RM11_GUI_V271_START\r\n");

    HMODULE user32=LoadLibraryW(L"user32.dll");
    if (!user32) finish("RM11_GUI_V271_USER32_LOAD_FAILED\r\n",71);
    write_line("RM11_GUI_V271_USER32_LOADED\r\n");

    HMODULE gdi32=LoadLibraryW(L"gdi32.dll");
    if (!gdi32) finish("RM11_GUI_V271_GDI32_LOAD_FAILED\r\n",72);
    write_line("RM11_GUI_V271_GDI32_LOADED\r\n");

    REG_CLASS register_class=(REG_CLASS)GetProcAddress(user32,"RegisterClassW");
    CREATE_WINDOW create_window=(CREATE_WINDOW)GetProcAddress(user32,"CreateWindowExW");
    DEF_PROC def_window_proc=(DEF_PROC)GetProcAddress(user32,"DefWindowProcW");
    SHOW_WINDOW show_window=(SHOW_WINDOW)GetProcAddress(user32,"ShowWindow");
    UPDATE_WINDOW update_window=(UPDATE_WINDOW)GetProcAddress(user32,"UpdateWindow");
    DESTROY_WINDOW destroy_window=(DESTROY_WINDOW)GetProcAddress(user32,"DestroyWindow");
    GET_DC get_dc=(GET_DC)GetProcAddress(user32,"GetDC");
    RELEASE_DC release_dc=(RELEASE_DC)GetProcAddress(user32,"ReleaseDC");
    GET_CAPS get_caps=(GET_CAPS)GetProcAddress(gdi32,"GetDeviceCaps");
    if (!register_class || !create_window || !def_window_proc || !show_window ||
        !update_window || !destroy_window || !get_dc || !release_dc || !get_caps)
        finish("RM11_GUI_V271_REQUIRED_API_MISSING\r\n",73);
    write_line("RM11_GUI_V271_REQUIRED_APIS_LOADED\r\n");
    g_def_window_proc=def_window_proc;
    WNDCLASSW wc={0};
    wc.lpfnWndProc=window_proc;
    wc.hInstance=GetModuleHandleW(NULL);
    wc.lpszClassName=klass;
    if (!register_class(&wc)) finish("RM11_GUI_V271_REGISTER_CLASS_FAILED\r\n",74);
    write_line("RM11_GUI_V271_WINDOW_CLASS_REGISTERED\r\n");
    HWND hwnd=create_window(0,klass,windowTitle,WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,CW_USEDEFAULT,500,280,NULL,NULL,wc.hInstance,NULL);
    if (!hwnd) finish("RM11_GUI_V271_CREATE_WINDOW_FAILED\r\n",75);
    write_line("RM11_GUI_V271_WINDOW_CREATED\r\n");
    HDC dc=get_dc(hwnd);
    if (dc) {
        int horz=get_caps(dc,HORZRES);
        int vert=get_caps(dc,VERTRES);
        if (horz>0 && vert>0) write_line("RM11_GUI_V271_GDI_DEVICE_CAPS_OK\r\n");
        else write_line("RM11_GUI_V271_GDI_DEVICE_CAPS_EMPTY\r\n");
        (void)release_dc(hwnd,dc);
    } else {
        write_line("RM11_GUI_V271_GET_DC_FAILED\r\n");
    }
    (void)show_window(hwnd,SW_SHOWNORMAL);
    (void)update_window(hwnd);
    write_line("RM11_GUI_V271_WINDOW_SHOW_REQUESTED\r\n");
    (void)destroy_window(hwnd);
    finish("RM11_GUI_V271_WIN32_WINDOW_API_SUCCESS_NOT_DISPLAY_PROOF\r\n",76);
}
