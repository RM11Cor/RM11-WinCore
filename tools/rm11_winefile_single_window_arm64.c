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

struct scan_state { int frames; int children_removed; int verified; };

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
    if(!IsZoomed(frame))ShowWindow(frame,SW_MAXIMIZE);
    HWND active=(HWND)SendMessageW(mdi,WM_MDIGETACTIVE,0,0);
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
            SendMessageW(mdi,WM_MDIDESTROY,(WPARAM)stale[i],0);
            state->children_removed++;
        }
    }
    if(IsWindow(active)) {
        // A maximized outer window is not enough: maximize active MDI child.
        SendMessageW(mdi,WM_MDIMAXIMIZE,(WPARAM)active,0);
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
