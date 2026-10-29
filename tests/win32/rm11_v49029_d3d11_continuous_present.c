/*
 * RM11 Windows x64 D3D11 PRESENT stress / color-changing proof.
 * MIT License. Mini test: no files, no networking, no game state modification.
 * Compile with mingw-w64 x86_64-w64-mingw32-gcc.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>
#include <stdint.h>

#define RM11_MAX_FRAMES 900
#define RM11_WIDTH 792
#define RM11_HEIGHT 466

static volatile LONG running=1;
static LRESULT CALLBACK wndproc(HWND wnd,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_DESTROY){InterlockedExchange(&running,0);PostQuitMessage(0);return 0;}
    if(msg==WM_CLOSE){DestroyWindow(wnd);return 0;}
    return DefWindowProcA(wnd,msg,wp,lp);
}
static void print_result(const char *step,HRESULT result){
    printf("RM11_V49029_STAGE=%s HRESULT=0x%08lX\n",step,(unsigned long)result);
    fflush(stdout);
}
int main(void){
    WNDCLASSEXA wc={0};
    HWND hwnd=NULL;
    IDXGISwapChain *swap=NULL;
    ID3D11Device *device=NULL;
    ID3D11DeviceContext *context=NULL;
    ID3D11Texture2D *backbuffer=NULL;
    ID3D11RenderTargetView *rtv=NULL;
    HRESULT hr=S_OK;
    int ok=0,frame=0,present_errors=0;
    LARGE_INTEGER freq={0},begin={0},now={0},last={0};
    printf("RM11_V49029_FRAME_TEST=BEGIN TARGET_FRAMES=%d WIDTH=%d HEIGHT=%d\n",
           RM11_MAX_FRAMES,RM11_WIDTH,RM11_HEIGHT);
    fflush(stdout);

    wc.cbSize=sizeof(wc);
    wc.lpfnWndProc=wndproc;
    wc.hInstance=GetModuleHandleA(NULL);
    wc.lpszClassName="RM11V49029FrameProof";
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    if(!RegisterClassExA(&wc)){print_result("WINDOW_CLASS_FAILED",HRESULT_FROM_WIN32(GetLastError()));goto cleanup;}
    hwnd=CreateWindowExA(0,wc.lpszClassName,"RM11 D3D11 Continuous Present v4.90.29",
        WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,
        RM11_WIDTH+16,RM11_HEIGHT+39,NULL,NULL,wc.hInstance,NULL);
    if(!hwnd){print_result("CREATE_WINDOW_FAILED",HRESULT_FROM_WIN32(GetLastError()));goto cleanup;}
    ShowWindow(hwnd,SW_SHOW);
    UpdateWindow(hwnd);

    DXGI_SWAP_CHAIN_DESC sc;
    ZeroMemory(&sc,sizeof(sc));
    sc.BufferDesc.Width=RM11_WIDTH;
    sc.BufferDesc.Height=RM11_HEIGHT;
    sc.BufferDesc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;
    sc.SampleDesc.Count=1;
    sc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sc.BufferCount=2;
    sc.OutputWindow=hwnd;
    sc.Windowed=TRUE;
    sc.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL requested=D3D_FEATURE_LEVEL_11_0;
    D3D_FEATURE_LEVEL actual=(D3D_FEATURE_LEVEL)0;
    hr=D3D11CreateDeviceAndSwapChain(NULL,D3D_DRIVER_TYPE_HARDWARE,NULL,0,
        &requested,1,D3D11_SDK_VERSION,&sc,&swap,&device,&actual,&context);
    print_result("CREATE_D3D11_DEVICE_SWAPCHAIN",hr);
    if(FAILED(hr)||!swap||!device||!context)goto cleanup;
    printf("RM11_V49029_D3D_FEATURE_LEVEL=0x%04X\n",(unsigned)actual);
    fflush(stdout);

    hr=IDXGISwapChain_GetBuffer(swap,0,&IID_ID3D11Texture2D,(void **)&backbuffer);
    print_result("GET_BACK_BUFFER",hr);
    if(FAILED(hr)||!backbuffer)goto cleanup;
    hr=ID3D11Device_CreateRenderTargetView(device,(ID3D11Resource *)backbuffer,NULL,&rtv);
    print_result("CREATE_RENDER_TARGET",hr);
    if(FAILED(hr)||!rtv)goto cleanup;
    ID3D11DeviceContext_OMSetRenderTargets(context,1,&rtv,NULL);

    if(!QueryPerformanceFrequency(&freq)||!QueryPerformanceCounter(&begin)){
        print_result("PERF_COUNTER_UNAVAILABLE",E_FAIL);
        goto cleanup;
    }
    last=begin;
    for(frame=0;frame<RM11_MAX_FRAMES && InterlockedCompareExchange(&running,1,1);frame++){
        MSG message;
        while(PeekMessageA(&message,NULL,0,0,PM_REMOVE)){
            if(message.message==WM_QUIT)InterlockedExchange(&running,0);
            TranslateMessage(&message);
            DispatchMessageA(&message);
        }
        if(!InterlockedCompareExchange(&running,1,1))break;
        // Cycle once per 60 frames: blue, green, red, yellow.
        static const FLOAT colors[4][4]={
            {0.02f,0.20f,0.95f,1.0f},
            {0.02f,0.85f,0.14f,1.0f},
            {0.95f,0.04f,0.08f,1.0f},
            {0.95f,0.76f,0.03f,1.0f}
        };
        int color=(frame/60)%4;
        ID3D11DeviceContext_ClearRenderTargetView(context,rtv,colors[color]);
        hr=IDXGISwapChain_Present(swap,1,0);
        if(FAILED(hr)){
            print_result("PRESENT_FAILED",hr);
            present_errors++;
            break;
        }
        if(frame==0 || (frame+1)%60==0){
            QueryPerformanceCounter(&now);
            double seconds=(double)(now.QuadPart-last.QuadPart)/(double)freq.QuadPart;
            printf("RM11_V49029_PRESENT_OK FRAME=%d COLOR=%d INTERVAL_MS=%.3f FPS=%.2f\n",
                frame+1,color,1000.0*seconds/(frame==0?1:60),
                (frame==0 || seconds<=0)?0.0:60.0/seconds);
            fflush(stdout);
            last=now;
        }
        Sleep(1);
    }
    QueryPerformanceCounter(&now);
    {
        double duration=(double)(now.QuadPart-begin.QuadPart)/(double)freq.QuadPart;
        printf("RM11_V49029_RESULT FRAMES=%d FAILED_PRESENTS=%d SECONDS=%.3f AVERAGE_FPS=%.2f USER_CLOSED=%d\n",
            frame,present_errors,duration,duration>0?frame/duration:0.0,
            !InterlockedCompareExchange(&running,1,1));
        fflush(stdout);
    }
    ok=(frame==RM11_MAX_FRAMES && present_errors==0);
cleanup:
    if(rtv)ID3D11RenderTargetView_Release(rtv);
    if(backbuffer)ID3D11Texture2D_Release(backbuffer);
    if(context)ID3D11DeviceContext_Release(context);
    if(device)ID3D11Device_Release(device);
    if(swap)IDXGISwapChain_Release(swap);
    if(hwnd && IsWindow(hwnd))DestroyWindow(hwnd);
    printf("RM11_V49029_FINAL=%s\n",ok?"COMPLETE":"INCOMPLETE");
    fflush(stdout);
    return ok?0:2;
}
