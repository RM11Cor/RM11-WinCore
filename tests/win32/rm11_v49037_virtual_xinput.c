/*
 * RM11 CarX Street Virtual XInput v49037.
 * Windows x64 PE DLL. Game-owned (app-private) native XInput1_4 /1_3 /9_1_0
 * shim; no hooks or global registry mutations.
 *
 * Android holds a 64-byte file-backed mmap, and writes a seqlock on change.
 * Wine uses CreateFileMapping/MapViewOfFile on that *same* file so GetState
 * is a constant-time memory read, not an Android keyboard/mouse synthetic key.
 * Game usage must be confirmed from the on-device reader counter.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <xinput.h>
#include <stdint.h>
#include <string.h>

#define RM11_MAGIC 0x524D3131u
#define RM11_VERSION 1u
#define RM11_SIZE 64u

/* Offset layout coordinated with RM11VirtualXInputV49037.java */
#pragma pack(push,1)
typedef struct {
    uint32_t magic;           /* 0 */
    uint32_t version;         /* 4 */
    volatile LONG sequence;   /* 8 : even when committed */
    uint32_t connected;       /* 12 */
    uint16_t buttons;         /* 16 */
    uint8_t lt;               /* 18 */
    uint8_t rt;               /* 19 */
    int16_t lx,ly,rx,ry;      /* 20-27 */
    uint32_t reserved;        /* 28 */
    volatile LONG reads;      /* 32 */
    uint8_t padding[28];      /* 36-63 */
} RM11_PAD;
#pragma pack(pop)

typedef char rm11_state_size_must_be_64[(sizeof(RM11_PAD)==RM11_SIZE)?1:-1];

static HANDLE mappedFile=INVALID_HANDLE_VALUE;
static HANDLE mapping=NULL;
static volatile RM11_PAD *pad=NULL;
static LONG initLock=0,enabled=1;

static void initialize_once(void) {
    if(InterlockedCompareExchange(&initLock,1,0)!=0)return;
    char filename[1024]={0};
    DWORD n=GetEnvironmentVariableA("RM11_V49037_XINPUT_STATE_WINPATH",filename,sizeof(filename));
    if(!n||n>=sizeof(filename))return;
    HANDLE fd=CreateFileA(filename,GENERIC_READ|GENERIC_WRITE,
             FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(fd==INVALID_HANDLE_VALUE)return;
    HANDLE map=CreateFileMappingA(fd,NULL,PAGE_READWRITE,0,RM11_SIZE,NULL);
    if(!map){CloseHandle(fd);return;}
    volatile RM11_PAD *view=(volatile RM11_PAD *)MapViewOfFile(map,FILE_MAP_READ|FILE_MAP_WRITE,0,0,RM11_SIZE);
    if(!view){CloseHandle(map);CloseHandle(fd);return;}
    mappedFile=fd;mapping=map;pad=view;
}
static DWORD snapshot(DWORD index,XINPUT_STATE *out) {
    if(index>0)return ERROR_DEVICE_NOT_CONNECTED;
    if(!out)return ERROR_BAD_ARGUMENTS;
    initialize_once();
    if(!pad)return ERROR_DEVICE_NOT_CONNECTED;
    RM11_PAD local;
    int attempt;
    for(attempt=0;attempt<4;attempt++){
        LONG seq1=pad->sequence;
        MemoryBarrier();
        if(seq1&1)continue;
        memcpy(&local,(const void *)pad,sizeof(local));
        MemoryBarrier();
        if(seq1==pad->sequence && !(seq1&1))break;
    }
    if(attempt==4||local.magic!=RM11_MAGIC||local.version!=RM11_VERSION
            ||!local.connected)return ERROR_DEVICE_NOT_CONNECTED;
    InterlockedIncrement((volatile LONG *)&pad->reads);
    ZeroMemory(out,sizeof(*out));
    out->dwPacketNumber=(DWORD)(local.sequence/2);
    if(InterlockedCompareExchange(&enabled,1,1)!=0){
        out->Gamepad.wButtons=local.buttons;
        out->Gamepad.bLeftTrigger=local.lt;
        out->Gamepad.bRightTrigger=local.rt;
        out->Gamepad.sThumbLX=local.lx;
        out->Gamepad.sThumbLY=local.ly;
        out->Gamepad.sThumbRX=local.rx;
        out->Gamepad.sThumbRY=local.ry;
    }
    return ERROR_SUCCESS;
}
__declspec(dllexport) DWORD WINAPI XInputGetState(DWORD index,XINPUT_STATE *state){
    return snapshot(index,state);
}
__declspec(dllexport) DWORD WINAPI XInputGetStateEx(DWORD index,XINPUT_STATE *state){
    return snapshot(index,state);
}
__declspec(dllexport) void WINAPI XInputEnable(BOOL enable){
    InterlockedExchange(&enabled,enable?1:0);
}
__declspec(dllexport) DWORD WINAPI XInputSetState(DWORD index,XINPUT_VIBRATION *vibration){
    (void)vibration;
    initialize_once();
    if(index||!pad||pad->magic!=RM11_MAGIC)return ERROR_DEVICE_NOT_CONNECTED;
    return ERROR_SUCCESS;  /* haptic passthrough not yet available */
}
__declspec(dllexport) DWORD WINAPI XInputGetCapabilities(DWORD index,DWORD flags,XINPUT_CAPABILITIES *cap){
    (void)flags;
    if(index||!cap)return ERROR_DEVICE_NOT_CONNECTED;
    initialize_once();
    if(!pad||pad->magic!=RM11_MAGIC||!pad->connected)return ERROR_DEVICE_NOT_CONNECTED;
    ZeroMemory(cap,sizeof(*cap));
    cap->Type=XINPUT_DEVTYPE_GAMEPAD;
    cap->SubType=XINPUT_DEVSUBTYPE_GAMEPAD;
    cap->Gamepad.wButtons=0xffff;
    cap->Gamepad.bLeftTrigger=255;
    cap->Gamepad.bRightTrigger=255;
    cap->Gamepad.sThumbLX=32767;
    cap->Gamepad.sThumbLY=32767;
    cap->Gamepad.sThumbRX=32767;
    cap->Gamepad.sThumbRY=32767;
    return ERROR_SUCCESS;
}
__declspec(dllexport) DWORD WINAPI XInputGetBatteryInformation(
        DWORD index,BYTE deviceType,XINPUT_BATTERY_INFORMATION *battery){
    (void)deviceType;
    if(index||!battery)return ERROR_DEVICE_NOT_CONNECTED;
    initialize_once();
    if(!pad||pad->magic!=RM11_MAGIC)return ERROR_DEVICE_NOT_CONNECTED;
    battery->BatteryType=BATTERY_TYPE_WIRED;
    battery->BatteryLevel=BATTERY_LEVEL_FULL;
    return ERROR_SUCCESS;
}
__declspec(dllexport) DWORD WINAPI XInputGetKeystroke(
        DWORD index,DWORD reserved,PXINPUT_KEYSTROKE stroke){
    (void)index;(void)reserved;(void)stroke;
    return ERROR_EMPTY;
}
__declspec(dllexport) DWORD WINAPI XInputGetDSoundAudioDeviceGuids(
        DWORD index,GUID *render,GUID *capture){
    if(index!=0)return ERROR_DEVICE_NOT_CONNECTED;
    if(render)ZeroMemory(render,sizeof(GUID));
    if(capture)ZeroMemory(capture,sizeof(GUID));
    return ERROR_SUCCESS;
}
__declspec(dllexport) DWORD WINAPI XInputGetAudioDeviceIds(
        DWORD index,LPWSTR render,UINT *renderCount,
        LPWSTR capture,UINT *captureCount){
    if(index!=0)return ERROR_DEVICE_NOT_CONNECTED;
    if(renderCount){if(render && *renderCount)render[0]=0;*renderCount=0;}
    if(captureCount){if(capture && *captureCount)capture[0]=0;*captureCount=0;}
    return ERROR_SUCCESS;
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){
    (void)instance;(void)reserved;
    if(reason==DLL_PROCESS_DETACH){
        if(pad){UnmapViewOfFile((LPCVOID)pad);pad=NULL;}
        if(mapping){CloseHandle(mapping);mapping=NULL;}
        if(mappedFile!=INVALID_HANDLE_VALUE){CloseHandle(mappedFile);mappedFile=INVALID_HANDLE_VALUE;}
    }
    return TRUE;
}
