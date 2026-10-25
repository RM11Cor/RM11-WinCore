package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.rm11.autocore.runtime.NovaWorkspaceFiles;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.RuntimeLayout;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A real persistent Android-native desktop SHELL hosted INSIDE
 * RM11NativeWineActivity over the live X11/Lorie surface.
 *
 * Unlike the Nova Launcher, this contains a desktop, persistent Desktop
 * directory, icons, actual file manager and taskbar/Start menu. Hiding it
 * exposes the unchanged real Wine X11 display; showing it does not restart
 * Wine. Real file operations are confined to NovaWorkspaceFiles.
 *
 * Not a Win32 shell replacement. Win32 windows use the X11 view underneath.
 */
public final class NovaDesktopSurface extends FrameLayout {
    private static final int BG=0xff06080d, SURFACE=0xff141820,
        DARK=0xff0c1018, PANEL=0xff1e2532, RED=0xfff04452,
        WHITE=0xfff6f7fa, MUTED=0xffa6aeba;
    private final Activity activity;
    private final RuntimeLayout layout;
    private final NovaWorkspaceFiles store;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final AtomicInteger desktopVersion=new AtomicInteger();
    private final AtomicInteger explorerVersion=new AtomicInteger();
    private final ArrayDeque<File> history=new ArrayDeque<>();
    private final FrameLayout stage;
    private final LinearLayout desktopGrid, fileRows, menuPanel;
    private final TextView location, stats;
    private TextView clock;
    private final LinearLayout explorerWindow;
    private final Runnable showWine, leaveToLauncher, diagnostics;
    private File desktopDirectory, shownFolder, copiedFile;
    private boolean moveClipboard;
    private boolean destroyed;
    private final Runnable clockTask=new Runnable(){
        @Override public void run(){
            if(destroyed)return;
            clock.setText(new SimpleDateFormat("HH:mm",Locale.ROOT).format(new Date()));
            handler.postDelayed(this,30000);
        }
    };

    public NovaDesktopSurface(Activity host, Runnable switchToWine,
            Runnable returnHome, Runnable openDiagnostics) throws Exception {
        super(host);
        activity=host;
        showWine=switchToWine;
        leaveToLauncher=returnHome;
        diagnostics=openDiagnostics;
        layout=new RuntimeLayout(host.getFilesDir().toPath(),
                new File(host.getApplicationInfo().nativeLibraryDir).toPath());
        store=new NovaWorkspaceFiles(host.getFilesDir());
        desktopDirectory=store.directory().toPath().resolve("Desktop").toFile();
        if(!desktopDirectory.exists())
            store.createFolder(store.directory(),"Desktop");
        if(!desktopDirectory.isDirectory()||Files.isSymbolicLink(desktopDirectory.toPath()))
            throw new IllegalStateException("Desktop directory unavailable");
        setBackground(wallpaper());
        setFocusableInTouchMode(true);
        setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        stage=this;

        LinearLayout screen=vertical();
        stage.addView(screen,new FrameLayout.LayoutParams(-1,-1));
        LinearLayout top=horizontal();
        top.setPadding(d(18),d(7),d(18),d(6));
        TextView title=text("RM11  /  NOVA DESKTOP",18,WHITE,true);
        top.addView(title,new LinearLayout.LayoutParams(0,d(38),1));
        TextView status=text("●  NATIVE DESKTOP   •   WINE READY WHEN AVAILABLE",10,RED,true);
        top.addView(status,lp(-2,38));
        screen.addView(top,lp(-1,52));

        ScrollView desktopArea=new ScrollView(host);
        desktopArea.setFillViewport(true);
        desktopGrid=vertical();
        desktopGrid.setPadding(d(18),d(6),d(10),d(12));
        desktopArea.addView(desktopGrid);
        desktopArea.setOnLongClickListener(v->{desktopMenu(v);return true;});
        screen.addView(desktopArea,new LinearLayout.LayoutParams(-1,0,1));

        LinearLayout bar=horizontal();
        bar.setPadding(d(7),d(3),d(9),d(3));
        bar.setBackgroundColor(0xff151a26);
        Button start=button("◈  START",this::toggleStart,RED,WHITE);
        bar.addView(start,lp(118,39));
        Button explorerTask=button("▣  File Explorer",()->showExplorer(desktopDirectory),PANEL,WHITE);
        bar.addView(explorerTask,lp(154,39));
        Button wineTask=button("▣  Windows / Wine",showWine,PANEL,WHITE);
        bar.addView(wineTask,lp(160,39));
        TextView flexible=text("",11,MUTED,false);
        bar.addView(flexible,new LinearLayout.LayoutParams(0,d(39),1));
        clock=text("",12,WHITE,true);
        clock.setGravity(Gravity.CENTER);
        bar.addView(clock,lp(72,39));
        screen.addView(bar,lp(-1,45));

        menuPanel=vertical();
        menuPanel.setBackground(panel(0xff1b2434,11));
        menuPanel.setPadding(d(7),d(7),d(7),d(7));
        menuButton("◫  Computer / الأقراص",()->showComputer());
        menuButton("▣  Nova Desktop",()->showExplorer(desktopDirectory));
        menuButton("◈  Nova Workspace",()->showExplorer(store.directory()));
        menuButton("⚙  التشخيصات",diagnostics);
        menuButton("▣  إظهار Windows",showWine);
        menuButton("⏻  الخروج إلى Nova Shell",leaveToLauncher);
        FrameLayout.LayoutParams menuParams=new FrameLayout.LayoutParams(
                d(260),d(309),Gravity.BOTTOM|Gravity.LEFT);
        menuParams.leftMargin=d(8);menuParams.bottomMargin=d(51);
        stage.addView(menuPanel,menuParams);
        menuPanel.setVisibility(GONE);

        explorerWindow=vertical();
        explorerWindow.setBackground(panel(DARK,12));
        explorerWindow.setPadding(d(8),d(8),d(8),d(7));
        LinearLayout windowTop=horizontal();
        TextView windowName=text("FILE EXPLORER   /   Nova Desktop",14,WHITE,true);
        windowTop.addView(windowName,new LinearLayout.LayoutParams(0,d(33),1));
        windowTop.addView(button("—",()->explorerWindow.setVisibility(GONE),PANEL,WHITE),lp(45,34));
        explorerWindow.addView(windowTop,lp(-1,38));

        LinearLayout nav=horizontal();
        nav.addView(button("←",this::backFolder,PANEL,RED),lp(45,33));
        nav.addView(button("↑",this::parentFolder,PANEL,RED),lp(45,33));
        nav.addView(button("↻",this::reload,PANEL,RED),lp(45,33));
        location=text("Computer",12,MUTED,false);
        location.setSingleLine(true);
        location.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        location.setPadding(d(8),0,d(2),0);
        nav.addView(location,new LinearLayout.LayoutParams(0,d(33),1));
        explorerWindow.addView(nav,lp(-1,36));

        LinearLayout commands=horizontal();
        commands.addView(button("+ Folder",()->create(true),PANEL,WHITE),lp(102,35));
        commands.addView(button("+ File",()->create(false),PANEL,WHITE),lp(90,35));
        commands.addView(button("Paste",this::paste,PANEL,WHITE),lp(82,35));
        commands.addView(button("Computer",this::showComputer,PANEL,WHITE),lp(105,35));
        explorerWindow.addView(commands,lp(-1,39));

        ScrollView items=new ScrollView(host);
        fileRows=vertical();
        fileRows.setPadding(d(3),d(6),d(3),d(3));
        items.addView(fileRows);
        explorerWindow.addView(items,new LinearLayout.LayoutParams(-1,0,1));

        stats=text("Desktop items",11,MUTED,false);
        explorerWindow.addView(stats,lp(-1,26));
        FrameLayout.LayoutParams windowParams=new FrameLayout.LayoutParams(
                -1,-1,Gravity.CENTER);
        windowParams.setMargins(d(145),d(76),d(70),d(68));
        stage.addView(explorerWindow,windowParams);
        explorerWindow.setVisibility(GONE);
        setOnClickListener(v->{if(menuPanel.getVisibility()==VISIBLE)menuPanel.setVisibility(GONE);});
        handler.post(clockTask);
        reloadDesktop();
        requestFocus();
    }

    private int d(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private GradientDrawable panel(int color,int radius){
        GradientDrawable g=new GradientDrawable();
        g.setColor(color);g.setCornerRadius(d(radius));
        g.setStroke(d(1),0xff3f3240);return g;
    }
    private GradientDrawable wallpaper(){
        GradientDrawable g=new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{BG,0xff111c2c,0xff340f20});
        return g;
    }
    private LinearLayout vertical(){
        LinearLayout l=new LinearLayout(activity);l.setOrientation(1);
        l.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);return l;
    }
    private LinearLayout horizontal(){
        LinearLayout l=new LinearLayout(activity);l.setOrientation(0);
        l.setGravity(Gravity.CENTER_VERTICAL);
        l.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);return l;
    }
    private LinearLayout.LayoutParams lp(int w,int h){
        return new LinearLayout.LayoutParams(w<0?w:d(w),h<0?h:d(h));
    }
    private TextView text(String content,int size,int color,boolean bold){
        TextView t=new TextView(activity);
        t.setText(content);t.setTextColor(color);t.setTextSize(size);
        t.setGravity(Gravity.CENTER_VERTICAL);
        if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        return t;
    }
    private Button button(String caption,Runnable action,int color,int ink){
        Button b=new Button(activity);
        b.setAllCaps(false);b.setText(caption);b.setTextSize(12);
        b.setTextColor(ink);b.setBackground(panel(color,7));
        b.setMinHeight(0);b.setMinimumHeight(0);
        b.setOnClickListener(v->action.run());
        return b;
    }
    private void menuButton(String name,Runnable task){
        Button b=button(name,()->{menuPanel.setVisibility(GONE);task.run();},PANEL,WHITE);
        LinearLayout.LayoutParams params=lp(-1,43);params.bottomMargin=d(3);
        menuPanel.addView(b,params);
    }
    private void toggleStart(){
        menuPanel.setVisibility(menuPanel.getVisibility()==VISIBLE?GONE:VISIBLE);
        if(menuPanel.getVisibility()==VISIBLE)menuPanel.bringToFront();
    }
    private void message(String msg){
        if(destroyed||activity.isFinishing())return;
        new AlertDialog.Builder(activity).setTitle("RM11 Nova Desktop")
            .setMessage(msg).setPositiveButton("OK",null).show();
    }
    private void prompt(String title,String suggested,
            java.util.function.Consumer<String> operation){
        EditText entry=new EditText(activity);
        entry.setSingleLine(true);entry.setText(suggested);entry.setSelectAllOnFocus(true);
        new AlertDialog.Builder(activity).setTitle(title).setView(entry)
            .setNegativeButton("Cancel",null)
            .setPositiveButton("Save",(dialog,which)->{
                String value=entry.getText().toString().trim();
                if(!value.isEmpty())operation.accept(value);
            }).show();
    }
    private boolean readable(File f){
        try{
            if(f==null||Files.isSymbolicLink(f.toPath()))return false;
            java.nio.file.Path p=f.getCanonicalFile().toPath();
            java.nio.file.Path home=activity.getFilesDir().getCanonicalFile().toPath();
            java.nio.file.Path c=layout.winePrefix.resolve("drive_c").toFile()
                    .getCanonicalFile().toPath();
            boolean local=p.equals(home)||p.startsWith(home);
            boolean wine=p.equals(c)||p.startsWith(c);
            File ext=Environment.getExternalStorageDirectory();
            java.nio.file.Path android=ext.getCanonicalFile().toPath();
            boolean phone=PhoneDriveBridge.authorized() &&
                    (p.equals(android)||p.startsWith(android));
            return local||wine||phone;
        }catch(Exception e){return false;}
    }
    private boolean writable(File f){return f!=null&&store.canEdit(f);}
    private void showComputer(){
        history.clear();shownFolder=null;
        explorerWindow.setVisibility(VISIBLE);
        reload();
    }
    private void showExplorer(File dir){
        if(dir!=null&&(!readable(dir)||!dir.isDirectory())){
            message("هذا المجلد غير متاح حالياً أو يحتاج صلاحية أندرويد.");
            return;
        }
        history.clear();shownFolder=dir;
        explorerWindow.setVisibility(VISIBLE);
        reload();
    }
    private void enter(File dir){
        if(dir==null||!readable(dir)||!dir.isDirectory()){
            message("تعذّر فتح هذا المجلد.");return;
        }
        if(shownFolder!=null)history.addLast(shownFolder);
        shownFolder=dir;reload();
    }
    private void backFolder(){
        if(history.isEmpty()){showComputer();return;}
        shownFolder=history.removeLast();reload();
    }
    private void parentFolder(){
        if(shownFolder==null)return;
        File parent=shownFolder.getParentFile();
        if(parent==null||!readable(parent))showComputer();
        else enter(parent);
    }
    private void fileMenu(File f){
        boolean edit=writable(f),ordinary=f.isFile();
        ArrayList<String> choices=new ArrayList<>();
        if(f.isDirectory())choices.add("Open folder");
        if(ordinary&&readable(f))choices.add("Copy");
        if(edit&&ordinary)choices.add("Cut");
        if(edit){choices.add("Rename");choices.add("Delete");}
        choices.add("Properties");
        new AlertDialog.Builder(activity).setTitle(f.getName())
            .setItems(choices.toArray(new String[0]),(dialog,index)->{
                String item=choices.get(index);
                switch(item){
                    case "Open folder":enter(f);break;
                    case "Copy":copiedFile=f;moveClipboard=false;message("اختير الملف للنسخ. افتح مجلد وجهته ثم اضغط Paste.");break;
                    case "Cut":copiedFile=f;moveClipboard=true;message("اختير الملف للنقل. افتح مجلد وجهته ثم اضغط Paste.");break;
                    case "Rename":prompt("Rename",f.getName(),name->doFileJob(
                        "إعادة التسمية",()->store.rename(f,name)));break;
                    case "Delete":
                        new AlertDialog.Builder(activity).setTitle("حذف الملف؟")
                            .setMessage(f.getName()+"\nالحذف نهائي، والمجلدات غير الفارغة محمية.")
                            .setNegativeButton("Cancel",null)
                            .setPositiveButton("Delete",(a,w)->doFileJob("الحذف",
                                    ()->{store.delete(f);return null;})).show();break;
                    default:message("المسار: "+f.getAbsolutePath()
                        +"\n"+(f.isDirectory()?"Folder":"File")
                        +"\nالملفات التنفيذية تُشغّل عبر محرك Wine، وليس بالنقر داخل الواجهة بعد.");
                }
            }).show();
    }
    private interface FileJob { Object run() throws Exception; }
    private void doFileJob(String label,FileJob job){
        io.execute(()->{
            String failure=null;
            try{job.run();}catch(Exception e){failure=e.getMessage();}
            String result=failure;
            handler.post(()->{
                if(destroyed)return;
                if(result!=null)message(label+": "+result);
                reloadDesktop();
                if(explorerWindow.getVisibility()==VISIBLE)reload();
            });
        });
    }
    private File target(){
        File dest=shownFolder;
        if(dest==null||!dest.isDirectory()||!writable(new File(dest,".write-probe"))){
            message("الكتابة مسموحة داخل Nova Workspace ومجلدات Desktop فقط. C وD للعرض.");
            return null;
        }
        return dest;
    }
    private void create(boolean folder){
        File dest=explorerWindow.getVisibility()==VISIBLE?target():desktopDirectory;
        if(dest==null)return;
        prompt(folder?"New folder":"New file",folder?"New Folder":"New File.txt",
            name->doFileJob("إنشاء",()->folder
                ?store.createFolder(dest,name):store.createFile(dest,name)));
    }
    private void paste(){
        File dest=explorerWindow.getVisibility()==VISIBLE?target():desktopDirectory;
        if(dest==null)return;
        if(copiedFile==null){message("اضغط مطوّلاً على ملف واختر Copy أو Cut أولاً.");return;}
        File source=copiedFile;
        boolean cut=moveClipboard;
        doFileJob(cut?"نقل":"نسخ",()->{
            File moved=cut?store.moveFile(source,dest):store.copyFile(source,dest);
            if(cut){copiedFile=null;moveClipboard=false;}
            return moved;
        });
    }
    private void desktopMenu(View anchor){
        PopupMenuCompat.menu(activity,anchor,new String[]{
            "New Folder","New File","Paste","File Explorer","Refresh"},
            index->{
                if(index==0)createDesktop(true);
                if(index==1)createDesktop(false);
                if(index==2)pasteDesktop();
                if(index==3)showExplorer(desktopDirectory);
                if(index==4)reloadDesktop();
            });
    }
    private void createDesktop(boolean folder){
        prompt(folder?"مجلد جديد على سطح المكتب":"ملف جديد على سطح المكتب",
                folder?"New Folder":"New File.txt",name->doFileJob("إنشاء",
                    ()->folder?store.createFolder(desktopDirectory,name):
                        store.createFile(desktopDirectory,name)));
    }
    private void pasteDesktop(){
        File source=copiedFile;if(source==null){message("اختر ملفاً للنسخ أولاً.");return;}
        boolean moving=moveClipboard;
        doFileJob(moving?"نقل":"نسخ",()->{
            File result=moving?store.moveFile(source,desktopDirectory):
                    store.copyFile(source,desktopDirectory);
            if(moving){copiedFile=null;moveClipboard=false;}
            return result;
        });
    }
    private void desktopShortcut(String text,String glyph,Runnable open,Runnable longClick,
            LinearLayout icons){
        LinearLayout cell=vertical();cell.setGravity(Gravity.CENTER);
        TextView picture=text(glyph,29,RED,true);picture.setGravity(Gravity.CENTER);
        cell.addView(picture,lp(100,44));
        TextView label=text(text,12,WHITE,false);
        label.setGravity(Gravity.TOP|Gravity.CENTER_HORIZONTAL);
        label.setMaxLines(2);label.setSingleLine(false);
        label.setEllipsize(android.text.TextUtils.TruncateAt.END);
        cell.addView(label,lp(110,43));
        cell.setBackground(panel(0x88141a26,8));
        cell.setOnClickListener(v->open.run());
        cell.setOnLongClickListener(v->{if(longClick!=null)longClick.run();return true;});
        LinearLayout.LayoutParams spec=lp(113,93);
        spec.rightMargin=d(9);spec.bottomMargin=d(8);
        icons.addView(cell,spec);
    }
    private void reloadDesktop(){
        final int id=desktopVersion.incrementAndGet();
        io.execute(()->{
            File[] raw=desktopDirectory.listFiles();
            ArrayList<File> paths=new ArrayList<>();
            if(raw!=null){
                Arrays.sort(raw,Comparator.comparing((File f)->!f.isDirectory())
                    .thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER));
                for(File p:raw)if(readable(p)&&paths.size()<200)paths.add(p);
            }
            handler.post(()->{
                if(destroyed||id!=desktopVersion.get())return;
                desktopGrid.removeAllViews();
                LinearLayout fixed=horizontal();
                desktopShortcut("Computer","▣",this::showComputer,null,fixed);
                desktopShortcut("File Explorer","▤",()->showExplorer(desktopDirectory),null,fixed);
                desktopShortcut("C: Windows","▣",
                    ()->showExplorer(layout.winePrefix.resolve("drive_c").toFile()),null,fixed);
                desktopShortcut("D: Phone","▥",()->
                    showExplorer(Environment.getExternalStorageDirectory()),null,fixed);
                desktopShortcut("New Folder","＋",()->createDesktop(true),null,fixed);
                desktopGrid.addView(fixed,lp(-1,103));
                // Fit icons to actual REDMAGIC landscape width and display inset.
                int columns=Math.max(2,Math.min(6,
                        (getResources().getDisplayMetrics().widthPixels-d(36))/d(122)));
                LinearLayout line=null;
                for(int i=0;i<paths.size();i++){
                    if(i%columns==0){line=horizontal();desktopGrid.addView(line,lp(-1,101));}
                    File p=paths.get(i);
                    desktopShortcut(p.getName(),p.isDirectory()?"▣":"▤",
                        ()->{if(p.isDirectory())showExplorer(p);else fileMenu(p);},
                        ()->fileMenu(p),line);
                }
                if(paths.isEmpty()){
                    TextView hint=text("مجلد Desktop فارغ. اختر New Folder أو اضغط مطوّلاً لإنشاء ملف.",12,MUTED,false);
                    desktopGrid.addView(hint,lp(-1,43));
                }
            });
        });
    }
    private void reload(){
        final int request=explorerVersion.incrementAndGet();
        final File folder=shownFolder;
        location.setText(folder==null?"Computer":folder.getAbsolutePath());
        io.execute(()->{
            ArrayList<File> files=new ArrayList<>();
            if(folder==null){
                files.add(store.directory());
                files.add(desktopDirectory);
                files.add(layout.winePrefix.resolve("drive_c").toFile());
                files.add(Environment.getExternalStorageDirectory());
            }else{
                File[] list=folder.listFiles();
                if(list!=null){
                    Arrays.sort(list,Comparator.comparing((File f)->!f.isDirectory())
                        .thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER));
                    for(File f:list)if(readable(f)&&files.size()<400)files.add(f);
                }
            }
            handler.post(()->{
                if(destroyed||explorerVersion.get()!=request)return;
                fileRows.removeAllViews();
                for(File f:files){
                    LinearLayout row=horizontal();
                    row.setPadding(d(6),d(2),d(6),d(2));
                    row.setBackground(panel(PANEL,6));
                    String caption=folder==null&&f.equals(store.directory())?"Nova Workspace":
                        folder==null&&f.equals(desktopDirectory)?"Desktop":
                        folder==null&&f.equals(layout.winePrefix.resolve("drive_c").toFile())?"C: Windows":
                        folder==null&&f.equals(Environment.getExternalStorageDirectory())?"D: Phone":
                        f.getName();
                    TextView name=text((f.isDirectory()?"▣  ":"▤  ")+caption,12,WHITE,false);
                    row.addView(name,new LinearLayout.LayoutParams(0,d(36),1));
                    TextView meta=text(f.isDirectory()?"FOLDER":"FILE",10,MUTED,false);
                    row.addView(meta,lp(72,36));
                    row.setOnClickListener(v->{
                        if(f.isDirectory())enter(f);else fileMenu(f);
                    });
                    row.setOnLongClickListener(v->{fileMenu(f);return true;});
                    LinearLayout.LayoutParams rp=lp(-1,38);rp.bottomMargin=d(4);
                    fileRows.addView(row,rp);
                }
                stats.setText(files.size()+" items  ·  Nova controls editable only in Workspace");
            });
        });
    }
    public boolean isOpen(){return getVisibility()==VISIBLE;}
    public void showDesktop(){
        if(destroyed)return;
        setVisibility(VISIBLE);
        bringToFront();reloadDesktop();requestFocus();
    }
    public void hideDesktop(){setVisibility(GONE);}
    public boolean onBack(){
        if(!isOpen())return false;
        if(menuPanel.getVisibility()==VISIBLE){menuPanel.setVisibility(GONE);return true;}
        if(explorerWindow.getVisibility()==VISIBLE){
            if(history.isEmpty())explorerWindow.setVisibility(GONE);
            else backFolder();
            return true;
        }
        toggleStart();return true;
    }
    public void shutdown(){
        destroyed=true;
        handler.removeCallbacks(clockTask);
        io.shutdownNow();
    }

    private static final class PopupMenuCompat {
        static void menu(Activity a,View anchor,String[] commands,
                java.util.function.IntConsumer onChoice){
            android.widget.PopupMenu p=new android.widget.PopupMenu(a,anchor);
            for(int i=0;i<commands.length;i++)
                p.getMenu().add(0,i,i,commands[i]);
            p.setOnMenuItemClickListener(choice->{onChoice.accept(choice.getItemId());return true;});
            p.show();
        }
    }
}
