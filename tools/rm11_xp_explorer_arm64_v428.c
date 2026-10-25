/*
 * RM11 XP Explorer Preview v4.0.28: actual ARM64 Win32 file manager.
 * New code licensed GPL-3.0-or-later. Keep Wine LGPL notices in packages.
 * This is an ISOLATED PREVIEW, never a silent replacement for stable Winefile.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_IE 0x0600
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <wchar.h>
#include <stdlib.h>

#define HOME L"::Computer"
#define HISTORY_MAX 32
enum {BAR=100,START,STARTPANEL,TASK,CLOCK,FRAME,TITLE,TREE,FILES,ADDRESS,STATUS,SEARCHBOX,
 GO=201,BACK,FORWARD,UP,REFRESH,COPY,CUT,PASTE,RENAME,CMD_DELETE,FOLDER,NEWFILE,SEARCH,
 MENU_FILES=301,MENU_NOTEPAD,MENU_CMD,MENU_WINECFG,MENU_RUN,MENU_EXIT};
typedef struct {WCHAR path[MAX_PATH];} Node;
typedef struct {WCHAR name[MAX_PATH];DWORD attrs;ULONGLONG size;FILETIME modified;} Item;
static HINSTANCE inst;
static HWND root,bar,start,startpanel,task,clocklabel,frame,title,tree,files,address,status,searchbox;
static WCHAR here[MAX_PATH]=HOME,back[HISTORY_MAX][MAX_PATH],forward[HISTORY_MAX][MAX_PATH],clipboard[MAX_PATH];
static int backCount,forwardCount,sortColumn;
static BOOL clipCut,menuVisible,synchronizing,sortAscending=TRUE;
static HBRUSH desktopBrush,taskBrush,titleBrush;

static void error_msg(const WCHAR *message){
 WCHAR buf[400];wsprintfW(buf,L"%s\nWindows error %lu",message,GetLastError());
 MessageBoxW(root,buf,L"RM11 Explorer",MB_OK|MB_ICONERROR);
}
static BOOL computer(void){return lstrcmpW(here,HOME)==0;}
static BOOL dir_exists(const WCHAR *p){
 DWORD a=GetFileAttributesW(p);return lstrcmpW(p,HOME)==0 ||
 (a!=INVALID_FILE_ATTRIBUTES && (a&FILE_ATTRIBUTE_DIRECTORY)!=0);
}
static void join(WCHAR *dst,const WCHAR *base,const WCHAR *name){
 if(wcslen(base)+wcslen(name)+2>=MAX_PATH){dst[0]=0;return;}
 lstrcpyW(dst,base);size_t len=wcslen(dst);
 if(len && dst[len-1]!=L'\\')lstrcatW(dst,L"\\");
 lstrcatW(dst,name);
}
static void push(WCHAR hist[][MAX_PATH],int *len,const WCHAR *val){
 if(*len>=HISTORY_MAX){MoveMemory(hist,hist+1,(HISTORY_MAX-1)*sizeof(hist[0]));--*len;}
 lstrcpynW(hist[(*len)++],val,MAX_PATH);
}
static int CALLBACK cmp(LPARAM p,LPARAM q,LPARAM column){
 const Item *a=(const Item*)p,*b=(const Item*)q;
 if(!a||!b)return 0;
 BOOL ad=(a->attrs&FILE_ATTRIBUTE_DIRECTORY)!=0,bd=(b->attrs&FILE_ATTRIBUTE_DIRECTORY)!=0;
 if(ad!=bd)return ad?-1:1;
 int d=0;
 if(column==2)d=a->size<b->size?-1:a->size>b->size?1:0;
 if(column==3)d=CompareFileTime(&a->modified,&b->modified);
 if(!d)d=lstrcmpiW(a->name,b->name);
 return sortAscending?d:-d;
}
static void add_item(const WCHAR *name,DWORD attrs,ULONGLONG size,FILETIME modified){
 Item *it=(Item*)calloc(1,sizeof(*it));if(!it)return;
 lstrcpynW(it->name,name,MAX_PATH);it->attrs=attrs;it->size=size;it->modified=modified;
 LVITEMW li={0};li.mask=LVIF_TEXT|LVIF_PARAM;li.iItem=ListView_GetItemCount(files);
 li.pszText=it->name;li.lParam=(LPARAM)it;
 int i=ListView_InsertItem(files,&li);if(i<0){free(it);return;}
 ListView_SetItemText(files,i,1,(attrs&FILE_ATTRIBUTE_DIRECTORY)?L"Folder":L"File");
 if(!(attrs&FILE_ATTRIBUTE_DIRECTORY)){
  WCHAR value[48];wsprintfW(value,L"%I64u",size);ListView_SetItemText(files,i,2,value);
 }
 SYSTEMTIME utc,local;
 if(FileTimeToSystemTime(&modified,&utc)&&SystemTimeToTzSpecificLocalTime(NULL,&utc,&local)){
  WCHAR date[40];wsprintfW(date,L"%04u-%02u-%02u %02u:%02u",
  local.wYear,local.wMonth,local.wDay,local.wHour,local.wMinute);
  ListView_SetItemText(files,i,3,date);
 }
}
static void refresh_list(void){
 WCHAR query[140];GetWindowTextW(searchbox,query,140);
 SendMessageW(files,WM_SETREDRAW,FALSE,0);
 ListView_DeleteAllItems(files);
 int count=0;
 if(computer()){
  WCHAR buf[512],*p=buf;DWORD n=GetLogicalDriveStringsW(511,buf);
  if(n>0&&n<511)while(*p){
   UINT type=GetDriveTypeW(p);FILETIME empty={0};
   if(type!=DRIVE_NO_ROOT_DIR&&type!=DRIVE_UNKNOWN&&(!query[0]||StrStrIW(p,query))){
    add_item(p,FILE_ATTRIBUTE_DIRECTORY,0,empty);count++;
   }
   p+=wcslen(p)+1;
  }
 }else{
  WCHAR glob[MAX_PATH];join(glob,here,L"*");
  WIN32_FIND_DATAW data;HANDLE h=FindFirstFileW(glob,&data);
  if(h!=INVALID_HANDLE_VALUE){
   do{
    if(!lstrcmpW(data.cFileName,L".")||!lstrcmpW(data.cFileName,L".."))continue;
    if(query[0]&&!StrStrIW(data.cFileName,query))continue;
    add_item(data.cFileName,data.dwFileAttributes,
      ((ULONGLONG)data.nFileSizeHigh<<32)|data.nFileSizeLow,data.ftLastWriteTime);
    count++;
   }while(count<10000&&FindNextFileW(h,&data));
   FindClose(h);
  }
 }
 ListView_SortItems(files,cmp,sortColumn);
 SendMessageW(files,WM_SETREDRAW,TRUE,0);InvalidateRect(files,NULL,FALSE);
 SetWindowTextW(address,here);SetWindowTextW(title,here);SetWindowTextW(task,here);
 WCHAR msg[310];wsprintfW(msg,L"%d item(s)  |  %s",count,here);SetWindowTextW(status,msg);
}
static void sync_tree_path(void);
static void navigate(const WCHAR *destination,BOOL remember){
 if(!dir_exists(destination)){error_msg(L"Directory not accessible.");return;}
 if(remember&&lstrcmpiW(here,destination)){
  push(back,&backCount,here);forwardCount=0;
 }
 lstrcpynW(here,destination,MAX_PATH);refresh_list();sync_tree_path();
}
static void up_one(void){
 if(computer())return;
 WCHAR value[MAX_PATH];lstrcpynW(value,here,MAX_PATH);
 size_t n=wcslen(value);while(n&&value[n-1]==L'\\')value[--n]=0;
 WCHAR *last=wcsrchr(value,L'\\');
 if(n<=2||!last){navigate(HOME,TRUE);return;}
 if(last==value+2)value[3]=0;else *last=0;
 navigate(value,TRUE);
}
static void history_step(BOOL previous){
 int *num=previous?&backCount:&forwardCount;
 WCHAR (*src)[MAX_PATH]=previous?back:forward;
 if(!*num)return;
 WCHAR dest[MAX_PATH];lstrcpynW(dest,src[*num-1],MAX_PATH);--*num;
 if(!dir_exists(dest)){MessageBeep(MB_ICONWARNING);return;}
 push(previous?forward:back,previous?&forwardCount:&backCount,here);
 navigate(dest,FALSE);
}
static Node *new_node(const WCHAR *path){
 Node *p=(Node*)calloc(1,sizeof(*p));if(p)lstrcpynW(p->path,path,MAX_PATH);return p;
}
static HTREEITEM tree_node(HTREEITEM parent,const WCHAR *label,const WCHAR *path){
 Node *n=new_node(path);if(!n)return NULL;
 TVINSERTSTRUCTW v={0};v.hParent=parent;v.hInsertAfter=TVI_LAST;
 v.item.mask=TVIF_TEXT|TVIF_PARAM|TVIF_CHILDREN;v.item.pszText=(LPWSTR)label;
 v.item.lParam=(LPARAM)n;v.item.cChildren=1;
 HTREEITEM item=TreeView_InsertItem(tree,&v);if(!item)free(n);return item;
}
static Node *tree_data(HTREEITEM h){
 TVITEMW v={0};v.mask=TVIF_PARAM;v.hItem=h;
 return TreeView_GetItem(tree,&v)?(Node*)v.lParam:NULL;
}
static void expand(HTREEITEM parent){
 Node *n=tree_data(parent);if(!n||TreeView_GetChild(tree,parent))return;
 if(!lstrcmpW(n->path,HOME)){
  WCHAR drives[512],*p=drives;DWORD k=GetLogicalDriveStringsW(511,drives);
  if(k>0&&k<511)while(*p){
   UINT t=GetDriveTypeW(p);if(t!=DRIVE_UNKNOWN&&t!=DRIVE_NO_ROOT_DIR)tree_node(parent,p,p);
   p+=wcslen(p)+1;
  }
  return;
 }
 WCHAR pattern[MAX_PATH];join(pattern,n->path,L"*");
 WIN32_FIND_DATAW fd;HANDLE h=FindFirstFileW(pattern,&fd);
 if(h==INVALID_HANDLE_VALUE)return;
 int count=0;
 do{
  if((fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) &&
     lstrcmpW(fd.cFileName,L".") && lstrcmpW(fd.cFileName,L"..")){
   WCHAR p[MAX_PATH];join(p,n->path,fd.cFileName);
   if(p[0])tree_node(parent,fd.cFileName,p);
   if(++count>=400)break;
  }
 }while(FindNextFileW(h,&fd));FindClose(h);
}
static void tree_init(void){
 synchronizing=TRUE;
 HTREEITEM c=tree_node(TVI_ROOT,L"Computer",HOME);
 WCHAR dest[MAX_PATH];
 if(SHGetFolderPathW(NULL,CSIDL_DESKTOPDIRECTORY,NULL,SHGFP_TYPE_CURRENT,dest)==S_OK
     &&dir_exists(dest))tree_node(TVI_ROOT,L"Desktop",dest);
 if(SHGetFolderPathW(NULL,CSIDL_PERSONAL,NULL,SHGFP_TYPE_CURRENT,dest)==S_OK
     &&dir_exists(dest))tree_node(TVI_ROOT,L"Documents",dest);
 if(c){expand(c);TreeView_Expand(tree,c,TVE_EXPAND);TreeView_SelectItem(tree,c);}
 synchronizing=FALSE;
}
/* Keep XP left-tree selection aligned with the actual current folder,
   including direct double-clicks in the right pane. Child enumeration is
   lazy, and changes only the existing TreeView; it never opens another HWND. */
static BOOL is_path_prefix(const WCHAR *full,const WCHAR *prefix){
 if(lstrcmpW(prefix,HOME)==0)return TRUE;
 size_t n=wcslen(prefix);
 return _wcsnicmp(full,prefix,n)==0 &&
       (!full[n] || full[n]==L'\\' || (n>0&&prefix[n-1]==L'\\'));
}
static void sync_tree_path(void){
 if(!tree)return;
 synchronizing=TRUE;
 HTREEITEM selectedNode=TreeView_GetRoot(tree);
 int best=-1;
 for(HTREEITEM t=TreeView_GetRoot(tree);t;t=TreeView_GetNextSibling(tree,t)){
  Node *p=tree_data(t);if(!p)continue;
  if(is_path_prefix(here,p->path)){
   int len=(int)wcslen(p->path);
   if(!lstrcmpW(p->path,HOME))len=0;
   if(len>best){best=len;selectedNode=t;}
  }
 }
 for(int depth=0;selectedNode && depth<28;depth++){
  Node *parent=tree_data(selectedNode);
  if(!parent||lstrcmpiW(parent->path,here)==0)break;
  expand(selectedNode);
  TreeView_Expand(tree,selectedNode,TVE_EXPAND);
  HTREEITEM matched=NULL;int length=-1;
  for(HTREEITEM child=TreeView_GetChild(tree,selectedNode);child;
      child=TreeView_GetNextSibling(tree,child)){
   Node *n=tree_data(child);if(!n||!is_path_prefix(here,n->path))continue;
   int size=(int)wcslen(n->path);
   if(size>length){matched=child;length=size;}
  }
  if(!matched)break;
  selectedNode=matched;
 }
 if(selectedNode){
  TreeView_SelectItem(tree,selectedNode);
  TreeView_EnsureVisible(tree,selectedNode);
 }
 synchronizing=FALSE;
}
static BOOL selected(WCHAR *full){
 int idx=ListView_GetNextItem(files,-1,LVNI_SELECTED);if(idx<0)return FALSE;
 LVITEMW row={0};row.iItem=idx;row.mask=LVIF_PARAM;
 if(!ListView_GetItem(files,&row))return FALSE;
 Item *it=(Item*)row.lParam;if(!it)return FALSE;
 if(computer())lstrcpynW(full,it->name,MAX_PATH);else join(full,here,it->name);
 return full[0]!=0;
}
static void execute(const WCHAR *path){
 HINSTANCE result=ShellExecuteW(root,L"open",path,NULL,NULL,SW_SHOWNORMAL);
 if((INT_PTR)result<=32)error_msg(L"Cannot run or open the selected file.");
}
static void activate(void){
 WCHAR p[MAX_PATH];if(!selected(p))return;
 if(dir_exists(p))navigate(p,TRUE);else execute(p);
}
static void create_item(BOOL folder){
 if(computer()){MessageBeep(MB_ICONWARNING);return;}
 for(int i=0;i<1000;i++){
  WCHAR name[80],path[MAX_PATH];
  if(i==0)lstrcpyW(name,folder?L"New Folder":L"New File.txt");
  else wsprintfW(name,folder?L"New Folder (%d)":L"New File (%d).txt",i);
  join(path,here,name);if(!path[0])return;
  if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES)continue;
  BOOL success=FALSE;
  if(folder)success=CreateDirectoryW(path,NULL);
  else{
   HANDLE h=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
   if(h!=INVALID_HANDLE_VALUE){CloseHandle(h);success=TRUE;}
  }
  if(success){refresh_list();return;}
  error_msg(L"Unable to create item.");return;
 }
}
static BOOL shell_op(UINT command,const WCHAR *source,const WCHAR *dest){
 WCHAR a[MAX_PATH+2]={0},b[MAX_PATH+2]={0};
 lstrcpynW(a,source,MAX_PATH);if(dest)lstrcpynW(b,dest,MAX_PATH);
 SHFILEOPSTRUCTW op={0};op.hwnd=root;op.wFunc=command;op.pFrom=a;op.pTo=dest?b:NULL;
 op.fFlags=(command==FO_DELETE)?FOF_ALLOWUNDO:FOF_NOCONFIRMMKDIR;
 int e=SHFileOperationW(&op);
 if(e||op.fAnyOperationsAborted){
  MessageBoxW(root,L"File operation failed or was cancelled.",L"RM11 Explorer",MB_OK|MB_ICONWARNING);
  return FALSE;
 }
 return TRUE;
}
static void stash(BOOL cut){
 if(selected(clipboard)){clipCut=cut;SetWindowTextW(status,cut?L"Selection ready to move":L"Selection ready to copy");}
}
static void paste(void){
 if(computer()||!clipboard[0])return;
 WCHAR *name=wcsrchr(clipboard,L'\\'),target[MAX_PATH];
 if(!name)return;join(target,here,name+1);
 if(!target[0]||!lstrcmpiW(target,clipboard))return;
 if(GetFileAttributesW(target)!=INVALID_FILE_ATTRIBUTES){
  MessageBoxW(root,L"Destination already exists. No files were overwritten.",
  L"RM11 Explorer",MB_OK|MB_ICONWARNING);return;
 }
 if(shell_op(clipCut?FO_MOVE:FO_COPY,clipboard,here)){
  if(clipCut)clipboard[0]=0;refresh_list();
 }
}
static void delete_selected(void){
 WCHAR p[MAX_PATH];if(!selected(p)||computer())return;
 if(MessageBoxW(root,L"Delete the selected file or folder?",L"Confirm delete",
     MB_YESNO|MB_ICONWARNING)!=IDYES)return;
 if(shell_op(FO_DELETE,p,NULL))refresh_list();
}
static void clock_update(void){
 SYSTEMTIME t;GetLocalTime(&t);WCHAR s[40];wsprintfW(s,L"%02d:%02d",t.wHour,t.wMinute);
 SetWindowTextW(clocklabel,s);
}
static void run_picker(void){
 WCHAR filename[MAX_PATH]=L"";
 static const WCHAR filter[]=L"Programs (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
 OPENFILENAMEW o={0};o.lStructSize=sizeof(o);o.hwndOwner=root;
 o.lpstrFile=filename;o.nMaxFile=MAX_PATH;o.lpstrFilter=filter;
 o.Flags=OFN_EXPLORER|OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
 if(GetOpenFileNameW(&o))execute(filename);
}
static LRESULT CALLBACK frame_proc(HWND hwnd,UINT msg,WPARAM w,LPARAM l){
 if(msg==WM_APP+1){refresh_list();return 0;}
 if(msg==WM_CTLCOLORSTATIC && (HWND)l==title){
  SetTextColor((HDC)w,RGB(255,255,255));SetBkColor((HDC)w,RGB(20,77,180));
  return (LRESULT)titleBrush;
 }
 if(msg==WM_COMMAND){
  switch(LOWORD(w)){
   case GO:{WCHAR p[MAX_PATH];GetWindowTextW(address,p,MAX_PATH);navigate(p,TRUE);break;}
   case BACK:history_step(TRUE);break;
   case FORWARD:history_step(FALSE);break;
   case UP:up_one();break;
   case REFRESH:refresh_list();break;
   case COPY:stash(FALSE);break;
   case CUT:stash(TRUE);break;
   case PASTE:paste();break;
   case CMD_DELETE:delete_selected();break;
   case FOLDER:create_item(TRUE);break;
   case NEWFILE:create_item(FALSE);break;
   case SEARCH:refresh_list();break;
   case RENAME:{
    int i=ListView_GetNextItem(files,-1,LVNI_SELECTED);
    if(i>=0&&!computer())ListView_EditLabel(files,i);break;
   }
  }
  return 0;
 }
 if(msg==WM_NOTIFY){
  NMHDR *h=(NMHDR*)l;
  if(h->idFrom==TREE){
   if(h->code==TVN_ITEMEXPANDINGW){NMTREEVIEWW *v=(NMTREEVIEWW*)l;
    if(v->action==TVE_EXPAND)expand(v->itemNew.hItem);
   }
   if(h->code==TVN_SELCHANGEDW && !synchronizing){
    NMTREEVIEWW *v=(NMTREEVIEWW*)l;Node *p=(Node*)v->itemNew.lParam;
    if(p)navigate(p->path,TRUE);
   }
   if(h->code==TVN_DELETEITEMW){NMTREEVIEWW *v=(NMTREEVIEWW*)l;free((void*)v->itemOld.lParam);}
  }else if(h->idFrom==FILES){
   if(h->code==LVN_DELETEITEM){NMLISTVIEW *v=(NMLISTVIEW*)l;free((void*)v->lParam);}
   if(h->code==NM_DBLCLK)activate();
   if(h->code==LVN_KEYDOWN){NMLVKEYDOWN *v=(NMLVKEYDOWN*)l;if(v->wVKey==VK_RETURN)activate();}
   if(h->code==LVN_COLUMNCLICK){
    NMLISTVIEW *v=(NMLISTVIEW*)l;
    if(sortColumn==v->iSubItem)sortAscending=!sortAscending;
    else{sortColumn=v->iSubItem;sortAscending=TRUE;}
    ListView_SortItems(files,cmp,sortColumn);
   }
   if(h->code==LVN_ENDLABELEDITW){
    NMLVDISPINFOW *v=(NMLVDISPINFOW*)l;
    if(v->item.pszText&&v->item.pszText[0]&&
       !wcspbrk(v->item.pszText,L"\\/:*?\"<>|")&&!computer()){
     LVITEMW t={0};t.iItem=v->item.iItem;t.mask=LVIF_PARAM;
     if(ListView_GetItem(files,&t)){
      Item *it=(Item*)t.lParam;WCHAR source[MAX_PATH],dest[MAX_PATH];
      join(source,here,it->name);join(dest,here,v->item.pszText);
      if(source[0]&&dest[0]&&GetFileAttributesW(dest)==INVALID_FILE_ATTRIBUTES &&
        MoveFileW(source,dest)){PostMessageW(hwnd,WM_APP+1,0,0);return TRUE;}
      error_msg(L"Rename failed or destination already exists.");
     }
    }return FALSE;
   }
  }
  return 0;
 }
 return DefWindowProcW(hwnd,msg,w,l);
}
static LRESULT CALLBACK controls_proc(HWND hwnd,UINT msg,WPARAM w,LPARAM l){
 if(msg==WM_DRAWITEM){
  DRAWITEMSTRUCT *di=(DRAWITEMSTRUCT*)l;
  if(di->CtlID==START){
   HBRUSH green=CreateSolidBrush(RGB(39,150,36));
   FillRect(di->hDC,&di->rcItem,green);DeleteObject(green);
   SetTextColor(di->hDC,RGB(255,255,255));SetBkMode(di->hDC,TRANSPARENT);
   DrawTextW(di->hDC,L"start",-1,&di->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
   return TRUE;
  }
 }
 if(msg==WM_COMMAND){SendMessageW(root,WM_COMMAND,w,l);return 0;}
 if(msg==WM_ERASEBKGND){
  RECT rect;GetClientRect(hwnd,&rect);FillRect((HDC)w,&rect,taskBrush);return 1;
 }
 if(msg==WM_CTLCOLORSTATIC){
  SetTextColor((HDC)w,RGB(255,255,255));SetBkColor((HDC)w,RGB(25,78,178));
  return (LRESULT)taskBrush;
 }
 return DefWindowProcW(hwnd,msg,w,l);
}
static void toggle_menu(void){
 menuVisible=!menuVisible;ShowWindow(startpanel,menuVisible?SW_SHOW:SW_HIDE);
 if(menuVisible)SetFocus(startpanel);
}
static LRESULT CALLBACK desktop_proc(HWND hwnd,UINT msg,WPARAM w,LPARAM l){
 if(msg==WM_SIZE && frame){RECT r;GetClientRect(root,&r);
  int width=r.right,height=r.bottom,barHeight=35;
  MoveWindow(bar,0,height-barHeight,width,barHeight,TRUE);
  MoveWindow(start,1,1,100,barHeight-2,TRUE);
  MoveWindow(task,106,4,width-220,27,TRUE);MoveWindow(clocklabel,width-104,4,100,27,TRUE);
  MoveWindow(startpanel,5,height-barHeight-208,245,206,TRUE);
  int fw=width*82/100,fh=(height-barHeight)*80/100;
  if(fw<700)fw=width-10;if(fh<350)fh=height-barHeight-8;
  MoveWindow(frame,5,4,fw,fh,TRUE);MoveWindow(title,0,0,fw,27,TRUE);
  const int keys[]={BACK,FORWARD,UP,REFRESH,COPY,CUT,PASTE,RENAME,CMD_DELETE,FOLDER,NEWFILE};
  int x=6;for(int i=0;i<11;i++){
   int bw=i>=9?95:70;
   MoveWindow(GetDlgItem(frame,keys[i]),x,29,bw,28,TRUE);x+=bw+3;
  }
  MoveWindow(address,8,61,fw-279,26,TRUE);
  MoveWindow(GetDlgItem(frame,GO),fw-265,61,45,26,TRUE);
  MoveWindow(searchbox,fw-216,61,150,26,TRUE);
  MoveWindow(GetDlgItem(frame,SEARCH),fw-63,61,54,26,TRUE);
  int tw=fw/4,top=92,bottom=fh-25;
  MoveWindow(tree,5,top,tw-6,bottom-top,TRUE);
  MoveWindow(files,tw,top,fw-tw-6,bottom-top,TRUE);
  MoveWindow(status,5,fh-24,fw-10,22,TRUE);return 0;
 }
 if(msg==WM_ERASEBKGND){
  RECT rect;GetClientRect(hwnd,&rect);FillRect((HDC)w,&rect,desktopBrush);return 1;
 }
 if(msg==WM_TIMER){clock_update();return 0;}
 if(msg==WM_COMMAND){
  switch(LOWORD(w)){
   case START:toggle_menu();break;
   case MENU_FILES:toggle_menu();ShowWindow(frame,SW_SHOW);navigate(HOME,TRUE);break;
   case MENU_NOTEPAD:toggle_menu();execute(L"notepad.exe");break;
   case MENU_CMD:toggle_menu();execute(L"cmd.exe");break;
   case MENU_WINECFG:toggle_menu();execute(L"winecfg.exe");break;
   case MENU_RUN:toggle_menu();run_picker();break;
   case MENU_EXIT:DestroyWindow(root);break;
  }return 0;
 }
 if(msg==WM_DESTROY){KillTimer(hwnd,1);PostQuitMessage(0);return 0;}
 return DefWindowProcW(hwnd,msg,w,l);
}
static BOOL register_class(const WCHAR *name,WNDPROC fn,HBRUSH brush){
 WNDCLASSEXW c={0};c.cbSize=sizeof(c);c.lpfnWndProc=fn;c.hInstance=inst;
 c.lpszClassName=name;c.hbrBackground=brush;c.hCursor=LoadCursorW(NULL,IDC_ARROW);
 return RegisterClassExW(&c)!=0;
}
static HWND make_button(HWND parent,int id,const WCHAR *label){
 return CreateWindowExW(0,L"BUTTON",label,WS_CHILD|WS_VISIBLE|
    (id==START?BS_OWNERDRAW:BS_PUSHBUTTON),
    0,0,75,26,parent,(HMENU)(INT_PTR)id,inst,NULL);
}
int WINAPI WinMain(HINSTANCE current,HINSTANCE previous,LPSTR cmd,int show){
 (void)previous;(void)cmd;(void)show;inst=current;
 INITCOMMONCONTROLSEX ic={sizeof(ic),ICC_TREEVIEW_CLASSES|ICC_LISTVIEW_CLASSES};
 InitCommonControlsEx(&ic);
 desktopBrush=CreateSolidBrush(RGB(55,166,216));
 taskBrush=CreateSolidBrush(RGB(25,78,178));titleBrush=CreateSolidBrush(RGB(20,77,180));
 if(!register_class(L"RM11XPDesktop428",desktop_proc,desktopBrush)||
    !register_class(L"RM11XPFrame428",frame_proc,(HBRUSH)(COLOR_WINDOW+1))||
    !register_class(L"RM11XPControls428",controls_proc,taskBrush))return 1;
 root=CreateWindowExW(0,L"RM11XPDesktop428",L"RM11 XP Desktop Preview",
    WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,CW_USEDEFAULT,CW_USEDEFAULT,1500,900,
    NULL,NULL,inst,NULL);if(!root)return 2;
 bar=CreateWindowExW(0,L"RM11XPControls428",L"",WS_CHILD|WS_VISIBLE,
    0,0,500,35,root,(HMENU)(INT_PTR)BAR,inst,NULL);
 start=make_button(bar,START,L"start");
 task=CreateWindowExW(0,L"STATIC",L"Computer",WS_CHILD|WS_VISIBLE,
    0,0,200,30,bar,(HMENU)(INT_PTR)TASK,inst,NULL);
 clocklabel=CreateWindowExW(0,L"STATIC",L"",WS_CHILD|WS_VISIBLE,
    0,0,90,28,bar,(HMENU)(INT_PTR)CLOCK,inst,NULL);
 startpanel=CreateWindowExW(WS_EX_CLIENTEDGE,L"RM11XPControls428",L"",
    WS_CHILD|WS_BORDER,0,0,245,207,root,(HMENU)(INT_PTR)STARTPANEL,inst,NULL);
 const WCHAR *menu[]={L"File Manager",L"Notepad",L"Command Prompt",L"Wine Configuration",
                       L"Run an EXE...",L"Exit Desktop"};
 for(int i=0;i<6;i++)MoveWindow(make_button(startpanel,MENU_FILES+i,menu[i]),
                                  6,6+i*32,229,28,TRUE);
 frame=CreateWindowExW(WS_EX_CLIENTEDGE,L"RM11XPFrame428",L"",
    WS_CHILD|WS_VISIBLE|WS_CLIPCHILDREN,0,0,1200,650,root,(HMENU)(INT_PTR)FRAME,inst,NULL);
 title=CreateWindowExW(0,L"STATIC",HOME,WS_CHILD|WS_VISIBLE,0,0,1100,27,
    frame,(HMENU)(INT_PTR)TITLE,inst,NULL);
 const WCHAR *buttons[]={L"Back",L"Forward",L"Up",L"Refresh",L"Copy",L"Cut",L"Paste",
                           L"Rename",L"Delete",L"New Folder",L"New File"};
 for(int i=0;i<11;i++)make_button(frame,BACK+i,buttons[i]);
 address=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",HOME,
    WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,0,0,500,25,frame,(HMENU)(INT_PTR)ADDRESS,inst,NULL);
 make_button(frame,GO,L"Go");
 searchbox=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",
    WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,0,0,150,25,frame,(HMENU)(INT_PTR)SEARCHBOX,inst,NULL);
 make_button(frame,SEARCH,L"Search");
 tree=CreateWindowExW(WS_EX_CLIENTEDGE,WC_TREEVIEWW,L"",
    WS_CHILD|WS_VISIBLE|TVS_HASBUTTONS|TVS_HASLINES|TVS_LINESATROOT|TVS_SHOWSELALWAYS,
    0,0,250,500,frame,(HMENU)(INT_PTR)TREE,inst,NULL);
 files=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",
    WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_EDITLABELS,
    0,0,750,500,frame,(HMENU)(INT_PTR)FILES,inst,NULL);
 ListView_SetExtendedListViewStyle(files,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
 const WCHAR *columns[]={L"Name",L"Type",L"Size",L"Modified"};
 const int widths[]={310,130,120,160};
 for(int i=0;i<4;i++){
  LVCOLUMNW c={0};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
  c.pszText=(LPWSTR)columns[i];c.cx=widths[i];c.iSubItem=i;
  ListView_InsertColumn(files,i,&c);
 }
 status=CreateWindowExW(0,L"STATIC",L"",WS_CHILD|WS_VISIBLE,
    0,0,100,22,frame,(HMENU)(INT_PTR)STATUS,inst,NULL);
 tree_init();refresh_list();
 ShowWindow(root,SW_SHOWMAXIMIZED);UpdateWindow(root);
 RECT r;GetClientRect(root,&r);
 SendMessageW(root,WM_SIZE,SIZE_RESTORED,MAKELPARAM(r.right,r.bottom));
 clock_update();SetTimer(root,1,30000,NULL);
 MSG message;while(GetMessageW(&message,NULL,0,0)>0){
  TranslateMessage(&message);DispatchMessageW(&message);
 }
 DeleteObject(desktopBrush);DeleteObject(taskBrush);DeleteObject(titleBrush);
 return (int)message.wParam;
}
