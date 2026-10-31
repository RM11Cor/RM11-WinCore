/* KERNIX isolated Windows x64 D3D12/ VKD3D-Proton engine probe.
 * No game files, no DRM, no user library or performance claims.
 * This checks D3D12 device, command queue and allocator. It does NOT create
 * a DXGI swapchain or present frames; those require a separate device proof.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define INITGUID
#include <windows.h>
#include <initguid.h>
#include <d3d12.h>
#include <stdio.h>
#include <string.h>

static FILE *out=NULL;
static void note(const char *stage,HRESULT hr){
    printf("KERNIX_V49103_D3D12_STAGE=%s HRESULT=0x%08lX\n",stage,(unsigned long)hr);
    fflush(stdout);
    if(out){
        fprintf(out,"KERNIX_V49103_D3D12_STAGE=%s HRESULT=0x%08lX\n",
                stage,(unsigned long)hr);
        fflush(out);
    }
}
int main(void){
    char filename[MAX_PATH];
    DWORD count=GetModuleFileNameA(NULL,filename,MAX_PATH);
    if(count>0 && count+53<MAX_PATH){
        char *slash=strrchr(filename,'\\');
        if(slash){
            slash[1]=0;
            strcat(filename,"KERNIX_D3D12_DEVICE_PROGRESS_V49103.txt");
            out=fopen(filename,"wb");
        }
    }
    ID3D12Device *device=NULL;
    ID3D12CommandQueue *queue=NULL;
    ID3D12CommandAllocator *allocator=NULL;
    HRESULT hr;
    int passed=0;
    note("PROGRAM_STARTED",S_OK);
    hr=D3D12CreateDevice(NULL,D3D_FEATURE_LEVEL_11_0,
                          &IID_ID3D12Device,(void**)&device);
    note("D3D12_CREATE_DEVICE",hr);
    if(FAILED(hr)||!device)goto done;
    D3D12_COMMAND_QUEUE_DESC desc={0};
    desc.Type=D3D12_COMMAND_LIST_TYPE_DIRECT;
    desc.Priority=D3D12_COMMAND_QUEUE_PRIORITY_NORMAL;
    desc.Flags=D3D12_COMMAND_QUEUE_FLAG_NONE;
    hr=ID3D12Device_CreateCommandQueue(device,&desc,
                     &IID_ID3D12CommandQueue,(void**)&queue);
    note("D3D12_CREATE_COMMAND_QUEUE",hr);
    if(FAILED(hr)||!queue)goto done;
    hr=ID3D12Device_CreateCommandAllocator(device,D3D12_COMMAND_LIST_TYPE_DIRECT,
                         &IID_ID3D12CommandAllocator,(void**)&allocator);
    note("D3D12_CREATE_COMMAND_ALLOCATOR",hr);
    if(FAILED(hr)||!allocator)goto done;
    passed=1;
done:
    if(allocator)ID3D12CommandAllocator_Release(allocator);
    if(queue)ID3D12CommandQueue_Release(queue);
    if(device)ID3D12Device_Release(device);
    note(passed?"D3D12_DEVICE_QUEUE_COMPLETE":"D3D12_DEVICE_QUEUE_INCOMPLETE",
         passed?S_OK:E_FAIL);
    if(out)fclose(out);
    return passed?0:47;
}
