/* Independent Windows x64 fiber stack-switch + SEH probe.
 * Runs on original Wine ARM64EC/FEX, without modifying the game or Wine.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define RM11_FIBER_EXCEPTION ((DWORD)0xe0420611u)
static void logline(const char *line) {
    HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written=0;
    if(output && output!=INVALID_HANDLE_VALUE)
        WriteFile(output,line,lstrlenA(line),&written,0);
}
typedef struct {
    void *mainFiber;
    volatile LONG result;
} FiberState;

__declspec(noinline) static void test_nested_frame(volatile LONG *result) {
    __try {
        RaiseException(RM11_FIBER_EXCEPTION,0,0,NULL);
        *result=-1;
    } __except(GetExceptionCode()==RM11_FIBER_EXCEPTION
                ?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH) {
        *result=61;
        logline("RM11_V461_FIBER_SEH_HANDLER_REACHED=YES\n");
    }
}
static VOID WINAPI run_on_fiber(LPVOID raw) {
    FiberState *state=(FiberState *)raw;
    logline("RM11_V461_FIBER_SWITCH_ENTERED=YES\n");
    test_nested_frame(&state->result);
    SwitchToFiber(state->mainFiber);
}
int main(void) {
    FiberState state={0,0};
    logline("RM11_V461_FIBER_PROBE_STARTED=x64\n");
    state.mainFiber=ConvertThreadToFiber(NULL);
    if(!state.mainFiber) {
        logline("RM11_V461_FIBER_CREATION_FAILED=CONVERT\n");
        return 62;
    }
    void *child=CreateFiber(0,run_on_fiber,&state);
    if(!child) {
        logline("RM11_V461_FIBER_CREATION_FAILED=CREATE\n");
        ConvertFiberToThread();
        return 63;
    }
    SwitchToFiber(child);
    DeleteFiber(child);
    ConvertFiberToThread();
    if(state.result!=61) {
        logline("RM11_V461_FIBER_PROBE_FAILED=SEH_ON_FIBER\n");
        return 64;
    }
    logline("RM11_V461_FIBER_SEH_PASS=YES\n");
    return 0;
}
