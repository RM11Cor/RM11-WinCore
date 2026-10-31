/*
 * KERNIX v49106: isolated Windows x64 D3D12 clear/Present test.
 * Source-built in GitHub CI. No game files, network, DRM or shared Wine edits.
 * 240 DirectX12-command-list color clears, with real queue/fence/Present.
 * Present returns and visible Android pixels are independent proof categories.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <initguid.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <cstdio>
#include <cstring>

static const UINT WIDTH=800, HEIGHT=470, COUNT=2, FRAMES=240;
static FILE* progress=nullptr;
static volatile LONG active=1;

static void mark(const char* name,HRESULT hr) {
    std::printf("KERNIX_V49106_STAGE=%s HRESULT=0x%08lX\n",name,(unsigned long)hr);
    std::fflush(stdout);
    if(progress){
        std::fprintf(progress,"KERNIX_V49106_STAGE=%s HRESULT=0x%08lX\n",
                     name,(unsigned long)hr);
        std::fflush(progress);
    }
}
static void frameMark(UINT frame,UINT color,HRESULT hr){
    std::printf("KERNIX_V49106_PRESENT FRAME=%u COLOR=%u HRESULT=0x%08lX\n",
        frame,color,(unsigned long)hr);
    std::fflush(stdout);
    if(progress){
        std::fprintf(progress,"KERNIX_V49106_PRESENT FRAME=%u COLOR=%u HRESULT=0x%08lX\n",
            frame,color,(unsigned long)hr);
        std::fflush(progress);
    }
}
static LRESULT CALLBACK windowProc(HWND h,UINT msg,WPARAM w,LPARAM l){
    if(msg==WM_CLOSE){DestroyWindow(h);return 0;}
    if(msg==WM_DESTROY){InterlockedExchange(&active,0);PostQuitMessage(0);return 0;}
    return DefWindowProcA(h,msg,w,l);
}
static void openProgress(){
    char path[MAX_PATH]={0};
    DWORD len=GetModuleFileNameA(nullptr,path,MAX_PATH);
    if(len==0||len>=MAX_PATH)return;
    char* sep=std::strrchr(path,'\\');
    if(!sep)return;
    const char* name="KERNIX_D3D12_FRAMES_PROGRESS_V49106.txt";
    if(static_cast<size_t>(sep-path)+1+std::strlen(name)>=MAX_PATH)return;
    sep[1]=0;
    std::strcat(path,name);
    progress=std::fopen(path,"wb");
}

int main(){
    openProgress();
    mark("PROGRAM_STARTED",S_OK);
    HWND window=nullptr;
    IDXGIFactory2* factory=nullptr;
    ID3D12Device* device=nullptr;
    ID3D12CommandQueue* queue=nullptr;
    IDXGISwapChain1* initialSwap=nullptr;
    IDXGISwapChain3* swap=nullptr;
    ID3D12DescriptorHeap* heap=nullptr;
    ID3D12Resource* buffers[COUNT]={nullptr,nullptr};
    ID3D12CommandAllocator* allocator=nullptr;
    ID3D12GraphicsCommandList* list=nullptr;
    ID3D12Fence* fence=nullptr;
    HANDLE eventHandle=nullptr;
    D3D12_CPU_DESCRIPTOR_HANDLE handles[COUNT]={};
    UINT64 timeline=0;
    HRESULT hr=E_FAIL;
    UINT rendered=0;
    bool passed=false;
    do {
        WNDCLASSEXA wc={};
        wc.cbSize=sizeof(wc);
        wc.hInstance=GetModuleHandleA(nullptr);
        wc.lpfnWndProc=windowProc;
        wc.lpszClassName="Kernix49106Dx12FrameWindow";
        wc.hCursor=LoadCursorA(nullptr,IDC_ARROW);
        if(!RegisterClassExA(&wc)){
            mark("CREATE_WINDOW_CLASS_FAILED",HRESULT_FROM_WIN32(GetLastError()));
            break;
        }
        window=CreateWindowExA(0,wc.lpszClassName,"KERNIX DirectX 12 Color Frames",
            WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,
            WIDTH+16,HEIGHT+39,nullptr,nullptr,wc.hInstance,nullptr);
        if(!window){mark("CREATE_WINDOW_FAILED",HRESULT_FROM_WIN32(GetLastError()));break;}
        ShowWindow(window,SW_SHOW);
        UpdateWindow(window);
        mark("CREATE_WINDOW",S_OK);

        hr=D3D12CreateDevice(nullptr,D3D_FEATURE_LEVEL_11_0,
            IID_ID3D12Device,reinterpret_cast<void**>(&device));
        mark("D3D12_CREATE_DEVICE",hr);
        if(FAILED(hr)||!device)break;

        D3D12_COMMAND_QUEUE_DESC queueDesc={};
        queueDesc.Type=D3D12_COMMAND_LIST_TYPE_DIRECT;
        hr=device->CreateCommandQueue(&queueDesc,IID_ID3D12CommandQueue,
            reinterpret_cast<void**>(&queue));
        mark("D3D12_CREATE_COMMAND_QUEUE",hr);
        if(FAILED(hr)||!queue)break;

        hr=CreateDXGIFactory1(IID_IDXGIFactory2,reinterpret_cast<void**>(&factory));
        mark("DXGI_CREATE_FACTORY",hr);
        if(FAILED(hr)||!factory)break;
        DXGI_SWAP_CHAIN_DESC1 sd={};
        sd.Width=WIDTH;
        sd.Height=HEIGHT;
        sd.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.SampleDesc.Count=1;
        sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.BufferCount=COUNT;
        sd.SwapEffect=DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.Scaling=DXGI_SCALING_STRETCH;
        sd.AlphaMode=DXGI_ALPHA_MODE_IGNORE;
        hr=factory->CreateSwapChainForHwnd(queue,window,&sd,nullptr,nullptr,&initialSwap);
        mark("DXGI_CREATE_SWAPCHAIN",hr);
        if(FAILED(hr)||!initialSwap)break;
        hr=initialSwap->QueryInterface(IID_IDXGISwapChain3,
            reinterpret_cast<void**>(&swap));
        mark("DXGI_SWAPCHAIN3",hr);
        if(FAILED(hr)||!swap)break;

        D3D12_DESCRIPTOR_HEAP_DESC hd={};
        hd.Type=D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
        hd.NumDescriptors=COUNT;
        hr=device->CreateDescriptorHeap(&hd,IID_ID3D12DescriptorHeap,
            reinterpret_cast<void**>(&heap));
        mark("D3D12_RTV_HEAP",hr);
        if(FAILED(hr)||!heap)break;
        const UINT stride=device->GetDescriptorHandleIncrementSize(
            D3D12_DESCRIPTOR_HEAP_TYPE_RTV);
        const D3D12_CPU_DESCRIPTOR_HANDLE base=heap->GetCPUDescriptorHandleForHeapStart();
        bool allBuffers=true;
        for(UINT i=0;i<COUNT;++i){
            hr=swap->GetBuffer(i,IID_ID3D12Resource,reinterpret_cast<void**>(&buffers[i]));
            if(FAILED(hr)||!buffers[i]){mark("DXGI_GET_BUFFER_FAILED",hr);allBuffers=false;break;}
            handles[i].ptr=base.ptr+i*stride;
            device->CreateRenderTargetView(buffers[i],nullptr,handles[i]);
        }
        if(!allBuffers)break;
        mark("D3D12_RENDER_TARGETS",S_OK);

        hr=device->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT,
            IID_ID3D12CommandAllocator,reinterpret_cast<void**>(&allocator));
        mark("D3D12_CREATE_COMMAND_ALLOCATOR",hr);
        if(FAILED(hr)||!allocator)break;
        hr=device->CreateCommandList(0,D3D12_COMMAND_LIST_TYPE_DIRECT,allocator,
            nullptr,IID_ID3D12GraphicsCommandList,reinterpret_cast<void**>(&list));
        mark("D3D12_CREATE_COMMAND_LIST",hr);
        if(FAILED(hr)||!list)break;
        hr=list->Close();
        if(FAILED(hr)){mark("D3D12_INITIAL_CLOSE_FAILED",hr);break;}
        hr=device->CreateFence(0,D3D12_FENCE_FLAG_NONE,IID_ID3D12Fence,
            reinterpret_cast<void**>(&fence));
        mark("D3D12_CREATE_FENCE",hr);
        if(FAILED(hr)||!fence)break;
        eventHandle=CreateEventA(nullptr,FALSE,FALSE,nullptr);
        if(!eventHandle){mark("CREATE_EVENT_FAILED",HRESULT_FROM_WIN32(GetLastError()));break;}

        static const FLOAT colors[4][4]={
            {0.02f,0.20f,0.95f,1.0f}, {0.02f,0.85f,0.14f,1.0f},
            {0.95f,0.04f,0.08f,1.0f}, {0.95f,0.76f,0.03f,1.0f}
        };
        mark("D3D12_COLOR_LOOP_STARTED",S_OK);
        for(UINT frame=0;frame<FRAMES && InterlockedCompareExchange(&active,1,1);++frame){
            MSG message;
            while(PeekMessageA(&message,nullptr,0,0,PM_REMOVE)){
                if(message.message==WM_QUIT)InterlockedExchange(&active,0);
                TranslateMessage(&message);
                DispatchMessageA(&message);
            }
            if(!InterlockedCompareExchange(&active,1,1))break;
            const UINT index=swap->GetCurrentBackBufferIndex();
            const UINT color=(frame/60)%4;
            hr=allocator->Reset();
            if(FAILED(hr)){mark("ALLOCATOR_RESET_FAILED",hr);break;}
            hr=list->Reset(allocator,nullptr);
            if(FAILED(hr)){mark("COMMAND_LIST_RESET_FAILED",hr);break;}
            D3D12_RESOURCE_BARRIER barrier={};
            barrier.Type=D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
            barrier.Transition.pResource=buffers[index];
            barrier.Transition.Subresource=D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
            barrier.Transition.StateBefore=D3D12_RESOURCE_STATE_PRESENT;
            barrier.Transition.StateAfter=D3D12_RESOURCE_STATE_RENDER_TARGET;
            list->ResourceBarrier(1,&barrier);
            list->OMSetRenderTargets(1,&handles[index],FALSE,nullptr);
            list->ClearRenderTargetView(handles[index],colors[color],0,nullptr);
            barrier.Transition.StateBefore=D3D12_RESOURCE_STATE_RENDER_TARGET;
            barrier.Transition.StateAfter=D3D12_RESOURCE_STATE_PRESENT;
            list->ResourceBarrier(1,&barrier);
            hr=list->Close();
            if(FAILED(hr)){mark("COMMAND_LIST_CLOSE_FAILED",hr);break;}
            ID3D12CommandList* cmds[1]={list};
            queue->ExecuteCommandLists(1,cmds);
            if(frame==0||frame%60==0)mark("BEFORE_PRESENT",S_OK);
            hr=swap->Present(0,0);
            if(frame==0||frame%60==0||FAILED(hr))
                frameMark(frame+1,color,hr);
            if(FAILED(hr)){mark("DXGI_PRESENT_FAILED",hr);break;}
            hr=queue->Signal(fence,++timeline);
            if(FAILED(hr)){mark("QUEUE_SIGNAL_FAILED",hr);break;}
            if(fence->GetCompletedValue()<timeline){
                hr=fence->SetEventOnCompletion(timeline,eventHandle);
                if(FAILED(hr)){mark("FENCE_SET_EVENT_FAILED",hr);break;}
                if(WaitForSingleObject(eventHandle,8000)!=WAIT_OBJECT_0){
                    mark("GPU_FENCE_TIMEOUT",E_FAIL);break;
                }
            }
            ++rendered;
            Sleep(33);
        }
        passed=(rendered==FRAMES);
        if(passed)mark("D3D12_FRAMES_PRESENT_COMPLETE",S_OK);
        else mark("D3D12_FRAMES_PRESENT_INCOMPLETE",E_FAIL);
    }while(false);
    std::printf("KERNIX_V49106_RESULT_FRAMES=%u EXPECTED=%u FAILED=%u\n",
        rendered,FRAMES,passed?0u:1u);
    std::fflush(stdout);
    if(progress){
        std::fprintf(progress,"KERNIX_V49106_RESULT_FRAMES=%u EXPECTED=%u FAILED=%u\n",
            rendered,FRAMES,passed?0u:1u);
        std::fflush(progress);
    }

    if(eventHandle)CloseHandle(eventHandle);
    if(fence)fence->Release();
    if(list)list->Release();
    if(allocator)allocator->Release();
    for(UINT i=0;i<COUNT;++i)if(buffers[i])buffers[i]->Release();
    if(heap)heap->Release();
    if(swap)swap->Release();
    if(initialSwap)initialSwap->Release();
    if(factory)factory->Release();
    if(queue)queue->Release();
    if(device)device->Release();
    if(window && IsWindow(window))DestroyWindow(window);
    if(progress)std::fclose(progress);
    return passed?0:47;
}
