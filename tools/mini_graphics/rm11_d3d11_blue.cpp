#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
static LRESULT CALLBACK proc(HWND w, UINT m, WPARAM a, LPARAM b){
 if(m==WM_CLOSE){DestroyWindow(w);return 0;}
 if(m==WM_DESTROY){PostQuitMessage(0);return 0;}
 return DefWindowProcA(w,m,a,b);
}
int WINAPI WinMain(HINSTANCE h,HINSTANCE prev,LPSTR args,int show){
 (void)prev;(void)args;(void)show;
 WNDCLASSA wc={};wc.hInstance=h;wc.lpfnWndProc=proc;wc.lpszClassName="RM11MiniD3D";
 wc.hCursor=LoadCursor(NULL,IDC_ARROW);
 if(!RegisterClassA(&wc))return 11;
 HWND w=CreateWindowExA(0,wc.lpszClassName,"RM11 MINI D3D11 - BLUE",WS_OVERLAPPEDWINDOW|WS_VISIBLE,
 CW_USEDEFAULT,CW_USEDEFAULT,800,500,NULL,NULL,h,NULL);
 if(!w)return 12;
 DXGI_SWAP_CHAIN_DESC desc={};
 desc.BufferDesc.Width=800;desc.BufferDesc.Height=500;
 desc.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
 desc.SampleDesc.Count=1;desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
 desc.BufferCount=2;desc.OutputWindow=w;desc.Windowed=TRUE;
 desc.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
 ID3D11Device *dev=NULL;ID3D11DeviceContext *ctx=NULL;IDXGISwapChain *swap=NULL;
 D3D_FEATURE_LEVEL level;
 HRESULT hr=D3D11CreateDeviceAndSwapChain(NULL,D3D_DRIVER_TYPE_HARDWARE,NULL,0,NULL,0,
 D3D11_SDK_VERSION,&desc,&swap,&dev,&level,&ctx);
 if(FAILED(hr)){MessageBoxA(w,"D3D11CreateDeviceAndSwapChain FAILED","RM11 D3D11 ERROR",MB_OK);DestroyWindow(w);return 21;}
 ID3D11Texture2D *tex=NULL;ID3D11RenderTargetView *view=NULL;
 hr=swap->GetBuffer(0,IID_ID3D11Texture2D,(void**)&tex);
 if(FAILED(hr))return 22;
 hr=dev->CreateRenderTargetView(tex,NULL,&view);
 tex->Release();
 if(FAILED(hr))return 23;
 DWORD start=GetTickCount();MSG msg;float blue[4]={0.03f,0.23f,0.95f,1.0f};
 while(GetTickCount()-start<30000){
  while(PeekMessageA(&msg,NULL,0,0,PM_REMOVE)){if(msg.message==WM_QUIT)goto done;TranslateMessage(&msg);DispatchMessageA(&msg);}
  ctx->ClearRenderTargetView(view,blue);
  hr=swap->Present(1,0);
  if(FAILED(hr)){MessageBoxA(w,"IDXGISwapChain::Present FAILED","RM11 D3D11 ERROR",MB_OK);break;}
  Sleep(16);
 }
 done:
 view->Release();ctx->Release();
 swap->Release();dev->Release();
 DestroyWindow(w);return FAILED(hr)?24:0;
}
