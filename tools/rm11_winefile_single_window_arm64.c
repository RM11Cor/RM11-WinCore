// RM11 Win32 single-window Winefile policy.
// Compiled for native Windows ARM64; Wine's own user32 handles the MDI HWNDs.
// No injection, X11 window spoofing, root, file IO, or data deletion.
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>

#define RM11_MAX_MDI_CHILDREN 64

static HWND find_mdi(HWND frame) {
    return FindWindowExW(frame, NULL, L"MDICLIENT", NULL);
}

static BOOL is_tree(HWND candidate) {
    WCHAR cls[40];
    int length=GetClassNameW(candidate,cls,(int)(sizeof(cls)/sizeof(cls[0])));
    return length>0 && lstrcmpW(cls,L"WFS_Tree")==0;
}

struct scan_state { int frames; int children_removed; int verified; int frame_resized; int child_resized; };
static void report_event(const char *value, DWORD count) {
    HANDLE handle=GetStdHandle(STD_OUTPUT_HANDLE);
    if(handle && handle!=INVALID_HANDLE_VALUE) {
        DWORD written=0;
        WriteFile(handle,value,count,&written,NULL);
    }
}
#define RM11_EVENT(s) report_event(s,(DWORD)(sizeof(s)-1))

static BOOL CALLBACK scan_frame(HWND frame, LPARAM state_value) {
    struct scan_state *state=(struct scan_state *)state_value;
    WCHAR cls[40];
    if(!GetClassNameW(frame,cls,40) || lstrcmpW(cls,L"WFS_Frame")!=0)
        return TRUE;
    HWND mdi=find_mdi(frame);
    if(!mdi)return TRUE;
    state->frames++;
    // Maximize the true top-level Winefile HWND using Win32 (not a guessed
    // keyboard shortcut). This is idempotent and scales with Wine DPI.
    if(!IsZoomed(frame)) {ShowWindow(frame,SW_MAXIMIZE);state->frame_resized++;}
    DWORD_PTR reply=0;
    if(!SendMessageTimeoutW(mdi,WM_MDIGETACTIVE,0,0,
            SMTO_ABORTIFHUNG|SMTO_BLOCK,350,&reply))return TRUE;
    HWND active=(HWND)reply;
    if(!active || !IsWindow(active) || !is_tree(active))return TRUE;
    HWND stale[RM11_MAX_MDI_CHILDREN];
    unsigned int count=0;
    for(HWND child=GetWindow(mdi,GW_CHILD);child;
        child=GetWindow(child,GW_HWNDNEXT)) {
        if(child!=active && is_tree(child)) {
            if(count<RM11_MAX_MDI_CHILDREN)stale[count++]=child;
            else return TRUE; // safety: never destroy a runaway window set
        }
    }
    for(unsigned int i=0;i<count;i++) {
        if(IsWindow(stale[i])) {
            // Winefile normally preserves a separate document HWND for
            // every drive. In single-pane mode keep ONLY the active drive.
            DWORD_PTR result=0;
            if(SendMessageTimeoutW(mdi,WM_MDIDESTROY,(WPARAM)stale[i],0,
                    SMTO_ABORTIFHUNG|SMTO_BLOCK,350,&result))
                state->children_removed++;
        }
    }
    if(IsWindow(active)) {
        // A maximized outer window is not enough: maximize active MDI child.
        if(!IsZoomed(active)) {
            DWORD_PTR result=0;
            if(SendMessageTimeoutW(mdi,WM_MDIMAXIMIZE,(WPARAM)active,0,
                    SMTO_ABORTIFHUNG|SMTO_BLOCK,350,&result))
                state->child_resized++;
        }
        state->verified++;
    }
    return TRUE;
}

// Self-terminates if Winefile has disappeared; never owns wineserver.
void WINAPI RM11Entry(void) {
    int foundEver=0, absentRounds=0;
    for(int round=0;round<21600;round++) { // bounded to <=3 hours
        struct scan_state state={0,0,0};
        EnumWindows(scan_frame,(LPARAM)&state);
        if(state.frame_resized)
            RM11_EVENT("RM11_V418_WIN32_WINEFILE_FRAME_MAXIMIZED\n");
        if(state.child_resized)
            RM11_EVENT("RM11_V418_WIN32_ACTIVE_MDI_MAXIMIZED\n");
        if(state.children_removed)
            RM11_EVENT("RM11_V418_WIN32_OLDER_MDI_DOCUMENT_CLOSED\n");
        if(state.frames>0) {
            foundEver=1;
            absentRounds=0;
        }else {
            absentRounds++;
            if(foundEver && absentRounds>=8)break;
            if(!foundEver && absentRounds>=90)break;
        }
        Sleep(500);
    }
    ExitProcess(0);
}
