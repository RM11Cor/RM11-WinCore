/*
 * Direct proof of Windows device visibility.
 * Independent PE64 executable: no private RM11 DLL import.
 * DLL calls and DirectInput device enumeration are captured separately.
 */
#define WIN32_LEAN_AND_MEAN
#define DIRECTINPUT_VERSION 0x0800
#define COBJMACROS
#include <windows.h>
#include <dinput.h>
#include <xinput.h>
#include <stdio.h>
#include <string.h>
typedef DWORD (WINAPI *XInputGetStateFn)(DWORD,XINPUT_STATE *);
typedef DWORD (WINAPI *XInputGetCapabilitiesFn)(DWORD,DWORD,XINPUT_CAPABILITIES *);
static unsigned int devices;
static BOOL CALLBACK enumerate(const DIDEVICEINSTANCEA *item,void *context){
    FILE *f=(FILE *)context;
    devices++;
    if(f && devices<=8)fprintf(f,"RM11_V49044_DINPUT_DEVICE_%u=%s\n",
        devices,item->tszProductName);
    return DIENUM_CONTINUE;
}
static const char *dlls[]={"xinput1_4.dll","xinput1_3.dll","xinput9_1_0.dll"};
int main(void){
    char path[1024]={0};
    DWORD chars=GetEnvironmentVariableA("RM11_V49044_PROBE_WINPATH",path,sizeof(path));
    FILE *f=NULL;
    if(chars>0 && chars<sizeof(path))f=fopen(path,"ab");
    if(!f)f=stdout;
    setvbuf(f,NULL,_IONBF,0); // Preserve the XInput answer even if DirectInput blocks.
    fprintf(f,"RM11_V49051_PROBE_ORDER=XINPUT_BEFORE_DIRECTINPUT\n");
    fprintf(f,"RM11_V49044_WIN_PROBE_STARTED=TRUE\n");
    HMODULE module=NULL;
    const char *selected="none";
    for(unsigned i=0;i<3 && !module;i++){
        module=LoadLibraryA(dlls[i]);
        if(module)selected=dlls[i];
    }
    XInputGetStateFn getState=NULL;
    XInputGetCapabilitiesFn getCaps=NULL;
    FARPROC stateProc=module?GetProcAddress(module,"XInputGetState"):NULL;
    FARPROC capsProc=module?GetProcAddress(module,"XInputGetCapabilities"):NULL;
    /* memcpy avoids a -Wcast-function-type conversion on 64-bit MinGW. */
    memcpy(&getState,&stateProc,sizeof(getState));
    memcpy(&getCaps,&capsProc,sizeof(getCaps));
    fprintf(f,"RM11_V49044_XINPUT_PROVIDER=%s\n",selected);
    if(module){
        char loaded[1024]={0};
        DWORD got=GetModuleFileNameA(module,loaded,sizeof(loaded));
        if(got>0 && got<sizeof(loaded))
            fprintf(f,"RM11_V49050_XINPUT_ACTUAL_DLL=%s\n",loaded);
    }
    char statePath[1024]={0};
    DWORD stateChars=GetEnvironmentVariableA(
        "RM11_V49037_XINPUT_STATE_WINPATH",statePath,sizeof(statePath));
    fprintf(f,"RM11_V49050_XINPUT_STATE_ENV_PRESENT=%s\n",
        (stateChars>0 && stateChars<sizeof(statePath))?"true":"false");
    if(getState){
        XINPUT_STATE state;
        memset(&state,0,sizeof(state));
        DWORD result=getState(0,&state);
        fprintf(f,"RM11_V49044_XINPUT_STATE_STATUS=%lu\n",(unsigned long)result);
        if(result==ERROR_SUCCESS){
            fprintf(f,"RM11_V49044_XINPUT_BUTTON_BITS=0x%04x\n",state.Gamepad.wButtons);
            fprintf(f,"RM11_V49044_XINPUT_AXIS_LX=%d\n",state.Gamepad.sThumbLX);
            fprintf(f,"RM11_V49044_XINPUT_LT_RT=%u,%u\n",
                        state.Gamepad.bLeftTrigger,state.Gamepad.bRightTrigger);
        }
    }else fprintf(f,"RM11_V49044_XINPUT_STATE_STATUS=NO_EXPORTED_FUNCTION\n");
    if(getCaps){
        XINPUT_CAPABILITIES cap;
        memset(&cap,0,sizeof(cap));
        DWORD result=getCaps(0,0,&cap);
        fprintf(f,"RM11_V49044_XINPUT_CAPABILITIES_STATUS=%lu\n",(unsigned long)result);
    }else fprintf(f,"RM11_V49044_XINPUT_CAPABILITIES_STATUS=NO_EXPORTED_FUNCTION\n");
    fprintf(f,"RM11_V49051_DIRECTINPUT_ENUMERATION_STARTED=TRUE\n");
    HINSTANCE h=GetModuleHandleA(NULL);
    LPDIRECTINPUT8A di=NULL;
    HRESULT hr=DirectInput8Create(h,0x0800,&IID_IDirectInput8A,(void **)&di,NULL);
    fprintf(f,"RM11_V49044_DIRECTINPUT8_CREATE_HRESULT=0x%08lx\n",(unsigned long)(DWORD)hr);
    if(SUCCEEDED(hr)&&di){
        HRESULT result=di->lpVtbl->EnumDevices(di,DI8DEVCLASS_GAMECTRL,
                                   enumerate,f,DIEDFL_ATTACHEDONLY);
        fprintf(f,"RM11_V49044_DINPUT_ENUM_HRESULT=0x%08lx\n",
                    (unsigned long)(DWORD)result);
        fprintf(f,"RM11_V49044_DINPUT_GAMECONTROLLER_COUNT=%u\n",devices);
        di->lpVtbl->Release(di);
    }else fprintf(f,"RM11_V49044_DINPUT_GAMECONTROLLER_COUNT=UNVERIFIED\n");
    fprintf(f,"RM11_V49044_EVIDENCE_NOTE=APIS_TESTED_IN_WINE_NOT_GAME_ACK\n");
    fflush(f);
    if(f!=stdout)fclose(f);
    if(module)FreeLibrary(module);
    return 0;
}
