#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static LRESULT CALLBACK proc(HWND w, UINT m, WPARAM a, LPARAM b) {
 if(m==WM_PAINT) {
  PAINTSTRUCT p; HDC dc=BeginPaint(w,&p); RECT r; GetClientRect(w,&r);
  HBRUSH bg=CreateSolidBrush(RGB(0,170,65)); FillRect(dc,&r,bg); DeleteObject(bg);
  SetBkMode(dc,TRANSPARENT); SetTextColor(dc,RGB(255,255,255));
  DrawTextA(dc,"RM11 GDI PASS - GREEN WINDOW",-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
  EndPaint(w,&p); return 0;
 }
 if(m==WM_CLOSE){DestroyWindow(w);return 0;}
 if(m==WM_DESTROY){PostQuitMessage(0);return 0;}
 return DefWindowProcA(w,m,a,b);
}
int WINAPI WinMain(HINSTANCE h,HINSTANCE prev,LPSTR args,int show){
 (void)prev;(void)args;
 WNDCLASSA wc={0}; wc.hInstance=h; wc.lpfnWndProc=proc;
 wc.lpszClassName="RM11MiniGDI"; wc.hCursor=LoadCursor(NULL,IDC_ARROW);
 if(!RegisterClassA(&wc))return 11;
 HWND w=CreateWindowExA(0,wc.lpszClassName,"RM11 MINI GDI - GREEN",WS_OVERLAPPEDWINDOW|WS_VISIBLE,
 CW_USEDEFAULT,CW_USEDEFAULT,800,500,NULL,NULL,h,NULL);
 if(!w)return 12;
 ShowWindow(w,SW_SHOW); UpdateWindow(w);
 DWORD start=GetTickCount();MSG msg;
 while(GetTickCount()-start<30000){
  while(PeekMessageA(&msg,NULL,0,0,PM_REMOVE)){if(msg.message==WM_QUIT)return 0;TranslateMessage(&msg);DispatchMessageA(&msg);}
  Sleep(16);
 }
 DestroyWindow(w);return 0;
}
