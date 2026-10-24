/*
 * RM11 v4 Windows GUI glyph oracle.
 *
 * Two separate gates: GDI must change pixels in a 32-bit memory DIB after
 * TextOutW("RM11 123 ABC"), AND the Android display must subsequently show
 * the same text. The second gate cannot be inferred from this program's
 * exit status or from an X11 handshake. No files/network or DRM.
 *
 * Compile as a Windows PE32+ program for the Wine target ABI with user32,
 * gdi32 and kernel32. Intended to run only after native X11 integration.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const WCHAR kText[] = L"RM11 123 ABC";
static int gResult = 70;

static void log_marker(const char *marker) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n=0, len=0;
    while (marker[len]) ++len;
    if (out && out != INVALID_HANDLE_VALUE)
        WriteFile(out,marker,len,&n,NULL);
    OutputDebugStringA(marker);
}

static BOOL paint_and_check(HWND window,HDC target) {
    BITMAPINFO bmi={0};
    HDC mem=NULL;
    HBITMAP dib=NULL;
    HGDIOBJ oldBmp=NULL,oldFont=NULL;
    HFONT font=NULL;
    void *pixels=NULL;
    RECT bounds={0,0,512,200};
    BOOL ok=FALSE;
    int x,y,changed=0;
    SIZE textSize={0};

    bmi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth=512;
    bmi.bmiHeader.biHeight=-200;  /* top-down DIB */
    bmi.bmiHeader.biPlanes=1;
    bmi.bmiHeader.biBitCount=32;
    bmi.bmiHeader.biCompression=BI_RGB;

    mem=CreateCompatibleDC(target);
    if(!mem)goto done;
    dib=CreateDIBSection(mem,&bmi,DIB_RGB_COLORS,&pixels,NULL,0);
    if(!dib || !pixels)goto done;
    oldBmp=SelectObject(mem,dib);
    if(!oldBmp || oldBmp==HGDI_ERROR)goto done;
    FillRect(mem,&bounds,(HBRUSH)GetStockObject(WHITE_BRUSH));

    font=CreateFontW(-42,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,
                     DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                     DEFAULT_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Tahoma");
    if(!font)goto done;
    oldFont=SelectObject(mem,font);
    if(!oldFont || oldFont==HGDI_ERROR)goto done;

    SetBkMode(mem,TRANSPARENT);
    SetTextColor(mem,RGB(0,0,0));
    if(!GetTextExtentPoint32W(mem,kText,12,&textSize)
       || textSize.cx<=0 || textSize.cy<=0)goto done;
    if(!TextOutW(mem,20,40,kText,12))goto done;
    GdiFlush();

    /* Only font rendering can change pixels: rectangle, cursor and borders
     * are NOT drawn into this source bitmap before the count. */
    for(y=35;y<130;y++)
        for(x=16;x<450;x++) {
            unsigned int p=((unsigned int*)pixels)[y*512+x]&0x00ffffffU;
            if(p!=0x00ffffffU)++changed;
        }
    if(changed>=30) {
        gResult=0;
        ok=TRUE;
        log_marker("RM11_V4_GDI_MEMORY_GLYPHS_NONBLANK\r\n");
    } else {
        gResult=72;
        log_marker("RM11_V4_GDI_MEMORY_GLYPHS_BLANK\r\n");
    }
    /* Actual Android visibility MUST be checked separately. */
    if(!BitBlt(target,0,0,512,200,mem,0,0,SRCCOPY))
        log_marker("RM11_V4_BITBLT_TO_WINDOW_FAILED\r\n");
    log_marker("RM11_V4_DISPLAY_VISIBILITY_UNVERIFIED\r\n");

done:
    if(!ok && gResult==70)
        log_marker("RM11_V4_GDI_DIB_RENDER_SETUP_FAILED\r\n");
    if(oldFont && oldFont!=HGDI_ERROR)SelectObject(mem,oldFont);
    if(font)DeleteObject(font);
    if(oldBmp && oldBmp!=HGDI_ERROR)SelectObject(mem,oldBmp);
    if(dib)DeleteObject(dib);
    if(mem)DeleteDC(mem);
    return ok;
}

static LRESULT CALLBACK window_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc=BeginPaint(w,&ps);
            paint_and_check(w,dc);
            EndPaint(w,&ps);
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(w);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(w,msg,wp,lp);
}

void mainCRTStartup(void) {
    HINSTANCE instance=GetModuleHandleW(NULL);
    WNDCLASSW type={0};
    HWND win;
    MSG message;
    type.lpfnWndProc=window_proc;
    type.hInstance=instance;
    type.lpszClassName=L"RM11NativeX11TextGate";
    type.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    if(!RegisterClassW(&type))ExitProcess(73);
    win=CreateWindowExW(0,type.lpszClassName,L"RM11 123 ABC - visible text test",
         WS_OVERLAPPEDWINDOW,90,90,640,310,NULL,NULL,instance,NULL);
    if(!win)ExitProcess(74);
    ShowWindow(win,SW_SHOWNORMAL);
    UpdateWindow(win);
    while(GetMessageW(&message,NULL,0,0)>0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess((UINT)gResult);
}
