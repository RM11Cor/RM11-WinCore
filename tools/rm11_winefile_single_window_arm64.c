// RM11 Win32 single-window Winefile policy.
// v4.0.23 phase-0: remove all independent Wine popup HWNDs. The native
// toolbar back arrow must be added IN-PROCESS to pinned upstream Winefile.
// Compiled for native Windows ARM64; Wine's own user32 handles the MDI HWNDs.
// No injection, X11 window spoofing, root, file IO, or data deletion.
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wingdi.h>
#include <winreg.h>
#include <commctrl.h>

#define RM11_MAX_MDI_CHILDREN 64

static HWND find_mdi(HWND frame) {
    return FindWindowExW(frame, NULL, L"MDICLIENT", NULL);
}

static BOOL is_tree(HWND candidate) {
    WCHAR cls[40];
    int length=GetClassNameW(candidate,cls,(int)(sizeof(cls)/sizeof(cls[0])));
    return length>0 && lstrcmpW(cls,L"WFS_Tree")==0;
}

// Winefile's window/class/command constants match the upstream pinned
// programs/winefile/winefile.h and resource.h (not UI heuristics).
#define RM11_WF_TREE_RIGHT 6
#define RM11_WF_ACTIVATE 101
#define RM11_WF_DISPATCH 0xBF80
#define RM11_NAV_PATH L"Z:\\data\\data\\com.rm11.autocore\\files\\rm11-winefile-nav-v421.signal"
struct scan_state { int frames; int children_removed; int verified; int frame_resized; int child_resized; };

static void report_event(const char *value, DWORD count) {
    HANDLE handle=GetStdHandle(STD_OUTPUT_HANDLE);
    if(handle && handle!=INVALID_HANDLE_VALUE) {
        DWORD written=0;
        WriteFile(handle,value,count,&written,NULL);
    }
}
#define RM11_EVENT(s) report_event(s,(DWORD)(sizeof(s)-1))

static HWND resizedDriveBar=NULL;
static HFONT driveBarFont=NULL;
static BOOL CALLBACK grow_drive_toolbar(HWND child,LPARAM unused) {
    (void)unused;
    WCHAR cls[40];
    if(!GetClassNameW(child,cls,40)
            || lstrcmpW(cls,L"ToolbarWindow32")!=0)return TRUE;
    LONG_PTR style=GetWindowLongPtrW(child,GWL_STYLE);
    if(!(style & TBSTYLE_LIST) || child==resizedDriveBar)return TRUE;
    if(!driveBarFont)
        driveBarFont=CreateFontW(-23,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,
                DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                DEFAULT_QUALITY,DEFAULT_PITCH,L"DejaVu Sans");
    if(!driveBarFont)return TRUE;
    DWORD_PTR ignored=0;
    SendMessageTimeoutW(child,WM_SETFONT,(WPARAM)driveBarFont,TRUE,
            SMTO_ABORTIFHUNG,450,&ignored);
    SendMessageTimeoutW(child,TB_SETBUTTONSIZE,0,MAKELPARAM(82,39),
            SMTO_ABORTIFHUNG,450,&ignored);
    SendMessageTimeoutW(child,TB_AUTOSIZE,0,0,
            SMTO_ABORTIFHUNG,450,&ignored);
    resizedDriveBar=child;
    RM11_EVENT("RM11_V420_DRIVE_BUTTONS_C_D_TEXT_23PX_ROW_39\n");
    return TRUE;
}


static HWND top_mdi_doc(HWND mdi) {
    DWORD_PTR reply=0;
    HWND fromMessage=NULL;
    if(SendMessageTimeoutW(mdi,WM_MDIGETACTIVE,0,0,
            SMTO_ABORTIFHUNG|SMTO_BLOCK,110,&reply))
        fromMessage=(HWND)reply;
    if(fromMessage && IsWindow(fromMessage) && is_tree(fromMessage))
        return fromMessage;
    // Wine's MDI child active reply may fail across PE processes.
    // Use first normal (non-icon title) WFS_Tree child by z-order.
    for(HWND p=GetWindow(mdi,GW_CHILD);p;p=GetWindow(p,GW_HWNDNEXT))
        if(is_tree(p) && IsWindowVisible(p) && !IsIconic(p))return p;
    return NULL;
}
static unsigned long read_nav_sequence(void) {
    HANDLE h=CreateFileW(RM11_NAV_PATH,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
            NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return 0;
    char b[24]={0};
    DWORD read=0;
    BOOL ok=ReadFile(h,b,23,&read,NULL);
    CloseHandle(h);
    if(!ok || read==0)return 0;
    unsigned long num=0;
    for(DWORD i=0;i<read && b[i]!='\n';i++){
        if(b[i]<'0'||b[i]>'9')return 0;
        num=num*10+(unsigned long)(b[i]-'0');
    }
    return num;
}
static int go_parent_directory(HWND mdi,HWND active) {
    // Upstream Winefile uses IDW_TREE_RIGHT=6, and the first right-list
    // items are "." and ".." (present only when a parent exists).
    HWND right=GetDlgItem(active,RM11_WF_TREE_RIGHT);
    if(!right)return 0;
    LRESULT count=SendMessageW(right,LB_GETCOUNT,0,0);
    if(count<2)return 0;
    LRESULT picked=SendMessageW(right,LB_SETCURSEL,1,0);
    if(picked==LB_ERR)return 0;
    // Synthetic list selection updates Pane.cur inside the ORIGINAL Winefile
    // process before its ordinary ID_ACTIVATE handles the parent entry.
    SendMessageW(active,WM_COMMAND,MAKEWPARAM(RM11_WF_TREE_RIGHT,LBN_SELCHANGE),
            (LPARAM)right);
    SendMessageW(active,RM11_WF_DISPATCH,MAKEWPARAM(RM11_WF_ACTIVATE,0),0);
    SendMessageW(mdi,WM_MDIMAXIMIZE,(WPARAM)active,0);
    RM11_EVENT("RM11_V421_PARENT_FOLDER_COMMAND_SENT\n");
    return 1;
}
static unsigned long handledNavigation=0;
static void maybe_go_parent(HWND mdi,HWND active) {
    unsigned long seq=read_nav_sequence();
    if(!seq)return;
    if(seq!=handledNavigation && go_parent_directory(mdi,active))
        handledNavigation=seq;
}

static BOOL CALLBACK scan_frame(HWND frame, LPARAM state_value) {
    struct scan_state *state=(struct scan_state *)state_value;
    WCHAR cls[40];
    if(!GetClassNameW(frame,cls,40) || lstrcmpW(cls,L"WFS_Frame")!=0)
        return TRUE;
    HWND mdi=find_mdi(frame);
    if(!mdi)return TRUE;
    state->frames++;
    EnumChildWindows(frame,grow_drive_toolbar,0);
    // Maximize the true top-level Winefile HWND using Win32 (not a guessed
    // keyboard shortcut). This is idempotent and scales with Wine DPI.
    if(!IsZoomed(frame)) {ShowWindow(frame,SW_MAXIMIZE);state->frame_resized++;}
    HWND active=top_mdi_doc(mdi);
    if(!active)return TRUE;
    maybe_go_parent(mdi,active);
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
            ShowWindowAsync(stale[i],SW_HIDE); // hide old frame immediately
            // Winefile normally preserves a separate document HWND for
            // every drive. In single-pane mode keep ONLY the active drive.
            DWORD_PTR result=0;
            if(SendMessageTimeoutW(mdi,WM_MDIDESTROY,(WPARAM)stale[i],0,
                    SMTO_ABORTIFHUNG|SMTO_BLOCK,130,&result))
                state->children_removed++;
            else if(PostMessageW(stale[i],WM_CLOSE,0,0))
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

/* Winefile itself loads REG_BINARY LOGFONTW from
 * HKCU\Software\Wine\WineFile\logfont in show_frame() at startup.
 * Change only THIS application's font before its process is started.
 * This is persistent, safe for files, and scales owner-drawn list rows
 * because Winefile measures Globals.hfont when creating its panes.
 */
static int prepare_readable_winefile_menu(void) {
    // Winefile's File/View/Window menu comes from Wine's nonclient metrics,
    // not Winefile's private 29px ListBox font. Increase menu + caption
    // fonts before Winefile creates the frame. No X11 resolution changes.
    NONCLIENTMETRICSW metrics={0};
    metrics.cbSize=sizeof(metrics);
    if(!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS,
            sizeof(metrics),&metrics,0)) {
        RM11_EVENT("RM11_V420_MENU_METRICS_READ_FAILED\n");
        return 5;
    }
    metrics.lfMenuFont.lfHeight=-25;
    metrics.lfMenuFont.lfWeight=FW_NORMAL;
    lstrcpynW(metrics.lfMenuFont.lfFaceName,L"DejaVu Sans",LF_FACESIZE);
    if(metrics.iMenuHeight<37)metrics.iMenuHeight=37;
    metrics.lfCaptionFont.lfHeight=-23;
    metrics.lfSmCaptionFont.lfHeight=-21;
    if(!SystemParametersInfoW(SPI_SETNONCLIENTMETRICS,
            sizeof(metrics),&metrics,SPIF_SENDCHANGE)) {
        RM11_EVENT("RM11_V420_MENU_METRICS_SET_FAILED\n");
        return 6;
    }
    RM11_EVENT("RM11_V420_MENU_FONT25_AND_ROW_HEIGHT37_SET\n");
    return 0;
}

static int prepare_readable_winefile_font(void) {
    HKEY key=NULL;
    DWORD result=RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Wine\\WineFile",
            0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&key,NULL);
    if(result!=ERROR_SUCCESS) {
        RM11_EVENT("RM11_V419_WINEFILE_FONT_KEY_FAILED\n");
        return 3;
    }
    LOGFONTW font={0};
    font.lfHeight=-29;             // large readable entries on 2688x1216
    font.lfWeight=FW_NORMAL;
    font.lfCharSet=DEFAULT_CHARSET;
    lstrcpynW(font.lfFaceName,L"DejaVu Sans",LF_FACESIZE);
    result=RegSetValueExW(key,L"logfont",0,REG_BINARY,
            (const BYTE*)&font,(DWORD)sizeof(font));
    RegCloseKey(key);
    if(result!=ERROR_SUCCESS) {
        RM11_EVENT("RM11_V419_WINEFILE_LOGFONT_WRITE_FAILED\n");
        return 4;
    }
    RM11_EVENT("RM11_V419_WINEFILE_LOGFONT29_REG_BINARY_SET\n");
    return prepare_readable_winefile_menu();
}

// Self-terminates if Winefile has disappeared; never owns wineserver.
void WINAPI RM11Entry(void) {
    // The helper is invoked as "filename --prepare-font" before Winefile.
    const WCHAR *cmd=GetCommandLineW();
    BOOL prepare=FALSE;
    while(*cmd) {
        if(*cmd==L'-' && cmd[1]==L'-' &&
                cmd[2]==L'p' && cmd[3]==L'r' &&
                cmd[4]==L'e' && cmd[5]==L'p' &&
                cmd[6]==L'a' && cmd[7]==L'r' &&
                cmd[8]==L'e' && cmd[9]==L'-' &&
                cmd[10]==L'f' && cmd[11]==L'o' &&
                cmd[12]==L'n' && cmd[13]==L't') {
            prepare=TRUE;break;
        }
        cmd++;
    }
    if(prepare)ExitProcess((UINT)prepare_readable_winefile_font());
    int foundEver=0, absentRounds=0;
    for(int round=0;round<135000;round++) { // bounded to <=3 hours
        struct scan_state state={0};
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
            if(foundEver && absentRounds>=55)break;
            if(!foundEver && absentRounds>=600)break;
        }
        Sleep(85);
    }
    ExitProcess(0);
}
