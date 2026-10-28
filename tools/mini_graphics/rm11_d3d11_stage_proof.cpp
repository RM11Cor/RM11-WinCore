#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <cstdio>
#include <cstring>
static char report[512]="STAGE 0: START";
static HWND windowHandle=NULL;
static void stage(const char* name,HRESULT hr) {
 std::snprintf(report,sizeof(report),"%s | HRESULT=0x%08lX",name,(unsigned long)hr);
 if(windowHandle){InvalidateRect(windowHandle,NULL,TRUE);UpdateWindow(windowHandle);}
}
static LRESULT CALLBACK wndproc(HWND w,UINT m,WPARAM a,LPARAM b) {
 if(m==WM_PAINT){
  PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);
  RECT r;GetClientRect(w,&r);
  RECT header=r;header.bottom=112;
  HBRUSH brush=CreateSolidBrush(RGB(35,44,63));FillRect(dc,&header,brush);DeleteObject(brush);
  SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(255,255,255));
  DrawTextA(dc,"RM11 D3D11 STAGE PROOF", -1,&header,DT_CENTER|DT_TOP|DT_SINGLELINE);
  RECT info=header;info.top=42;
  DrawTextA(dc,report,-1,&info,DT_CENTER|DT_TOP|DT_SINGLELINE);
  EndPaint(w,&ps);return 0;
 }
 if(m==WM_DESTROY){PostQuitMessage(0);return 0;}
 return DefWindowProcA(w,m,a,b);
}
int WINAPI WinMain(HINSTANCE h,HINSTANCE,LPSTR,int){
 WNDCLASSA wc={};wc.hInstance=h;wc.lpfnWndProc=wndproc;
 wc.lpszClassName="RM11D3D11StageProof";wc.hCursor=LoadCursor(NULL,IDC_ARROW);
 wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
 if(!RegisterClassA(&wc))return 11;
 windowHandle=CreateWindowExA(0,wc.lpszClassName,"RM11 D3D11 Stage Proof",
  WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,800,500,NULL,NULL,h,NULL);
 if(!windowHandle)return 12;
 ShowWindow(windowHandle,SW_SHOW);UpdateWindow(windowHandle);
 stage("STAGE 1: WINDOW CREATED",S_OK);
 DXGI_SWAP_CHAIN_DESC desc={};
 desc.BufferDesc.Width=800;desc.BufferDesc.Height=500;
 desc.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
 desc.SampleDesc.Count=1;desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
 desc.BufferCount=2;desc.OutputWindow=windowHandle;desc.Windowed=TRUE;
 desc.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
 ID3D11Device* device=NULL;ID3D11DeviceContext* context=NULL;
 IDXGISwapChain* swap=NULL;D3D_FEATURE_LEVEL level={};
 stage("STAGE 2: CREATING D3D11 DEVICE + SWAPCHAIN",S_OK);
 HRESULT hr=D3D11CreateDeviceAndSwapChain(NULL,D3D_DRIVER_TYPE_HARDWARE,NULL,0,NULL,0,
  D3D11_SDK_VERSION,&desc,&swap,&device,&level,&context);
 ID3D11Texture2D* texture=NULL;ID3D11RenderTargetView* target=NULL;
 if(FAILED(hr)){stage("FAIL: D3D11CreateDeviceAndSwapChain",hr);goto idle;}
 stage("STAGE 3: DEVICE + SWAPCHAIN OK",hr);
 hr=swap->GetBuffer(0,IID_ID3D11Texture2D,(void**)&texture);
 if(FAILED(hr)){stage("FAIL: GetBuffer",hr);goto idle;}
 hr=device->CreateRenderTargetView(texture,NULL,&target);
 texture->Release();texture=NULL;
 if(FAILED(hr)){stage("FAIL: CreateRenderTargetView",hr);goto idle;}
 stage("STAGE 4: RENDER TARGET OK",hr);
 {
  const float blue[4]={0.02f,0.22f,0.98f,1.0f};
  context->ClearRenderTargetView(target,blue);
  hr=swap->Present(1,0);
  if(FAILED(hr))stage("FAIL: IDXGISwapChain::Present",hr);
  else stage("STAGE 5: PRESENT RETURNED SUCCESS",hr);
 }
 idle:
 DWORD start=GetTickCount();MSG msg;
 while(GetTickCount()-start<30000){
  while(PeekMessageA(&msg,NULL,0,0,PM_REMOVE)){
   if(msg.message==WM_QUIT)goto end;
   TranslateMessage(&msg);DispatchMessageA(&msg);
  }
  Sleep(20);
 }
 end:
 if(target)target->Release();if(texture)texture->Release();
 if(context)context->Release();if(swap)swap->Release();if(device)device->Release();
 DestroyWindow(windowHandle);return 0;
}
