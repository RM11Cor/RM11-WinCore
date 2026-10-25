package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.graphics.Insets;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.text.TextUtils;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.XpExplorerPreviewHelper;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * v429 stability recovery: XP-look ANDROID-NATIVE file/desktop UI.
 * File list/navigation does not depend on Wine/X11 at all.
 * Wine and existing launchers are unchanged and callable separately.
 * Source and operations use Android permissions, not raw unrestricted Z:.
 * No root, no overlays, no automatic soft keyboard.
 */
public final class RM11XpNativeShellActivity extends Activity {
    private static final int DESKTOP=0xff36a7d8,BLUE=0xff0754bb,DARKBLUE=0xff143c99,
        WHITE=Color.WHITE,SOFT=0xffeaf1fd,INK=0xff16223a,GREEN=0xff159632;
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final AtomicInteger generation=new AtomicInteger();
    private final ArrayDeque<File> back=new ArrayDeque<>(),forward=new ArrayDeque<>();
    private RuntimeLayout layout;
    private LinearLayout list,tree,toolbar,taskbar;
    private TextView currentPath,status,windowTitle,taskLabel,clock;
    private EditText search;
    private FrameLayout desktop;
    private LinearLayout startMenu;
    private File here,selection,buffer;
    private boolean cut,showStart;
    private int sort=0;
    private final String ROOT="Computer";
    private final ArrayList<File> shown=new ArrayList<>();
    private static final int LIMIT=600;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN
                |WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        layout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
        // Disable known-bad Win32 XP preview globally. It must not be
        // relaunched unexpectedly after viewing this native shell.
        getSharedPreferences(XpExplorerPreviewHelper.PREFS,Context.MODE_PRIVATE)
                .edit().putBoolean(XpExplorerPreviewHelper.KEY,false).apply();
        drawDesktop();
        navigate(null,false);
        OfflineDiagnosticJournal.record(this,"v429-native-shell",
                "RM11_V429_ANDROID_NATIVE_XP_SHELL_VISIBLE_NO_WINE_X11_DEPENDENCY");
    }
    private int d(int px){return Math.round(px*getResources().getDisplayMetrics().density);}
    private GradientDrawable bg(int color,int rad){
        GradientDrawable a=new GradientDrawable();a.setColor(color);
        a.setCornerRadius(d(rad));return a;
    }
    private LinearLayout row(){
        LinearLayout v=new LinearLayout(this);v.setOrientation(0);
        v.setGravity(Gravity.CENTER_VERTICAL);v.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        return v;
    }
    private LinearLayout col(){
        LinearLayout v=new LinearLayout(this);v.setOrientation(1);
        v.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);return v;
    }
    private LinearLayout.LayoutParams ll(int w,int h){
        return new LinearLayout.LayoutParams(w<0?w:d(w),h<0?h:d(h));
    }
    private TextView label(String s,int sp,int color,boolean bold){
        TextView v=new TextView(this);v.setText(s);v.setTextSize(sp);
        v.setTextColor(color);v.setGravity(Gravity.CENTER_VERTICAL);
        v.setSingleLine(true);v.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        if(bold)v.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        return v;
    }
    private Button button(String title,Runnable action,int color){
        Button v=new Button(this);
        v.setText(title);v.setAllCaps(false);v.setTextSize(12);
        v.setTextColor(color==GREEN?WHITE:INK);v.setBackground(bg(color,4));
        v.setOnClickListener(w->action.run());v.setFocusableInTouchMode(false);
        return v;
    }
    private void makeTool(String title,Runnable action){
        Button v=button(title,action,SOFT);LinearLayout.LayoutParams p=ll(81,35);
        p.rightMargin=d(3);toolbar.addView(v,p);
    }
    private void startItem(String title,Runnable action){
        Button v=button(title,()->{toggleStart();action.run();},SOFT);
        LinearLayout.LayoutParams p=ll(-1,36);p.bottomMargin=d(2);
        startMenu.addView(v,p);
    }
    private void drawDesktop(){
        desktop=new FrameLayout(this);desktop.setBackgroundColor(DESKTOP);
        setContentView(desktop);
        LinearLayout shell=col();
        FrameLayout.LayoutParams fill=new FrameLayout.LayoutParams(-1,-1);
        shell.setPadding(d(4),d(3),d(4),d(0));desktop.addView(shell,fill);
        LinearLayout window=col();window.setBackgroundColor(WHITE);
        FrameLayout.LayoutParams frame=new FrameLayout.LayoutParams(-1,-1);
        LinearLayout.LayoutParams win=new LinearLayout.LayoutParams(-1,0,1);
        win.rightMargin=d(14);win.bottomMargin=d(9);
        shell.addView(window,win);
        LinearLayout caption=row();caption.setBackground(bg(BLUE,3));
        windowTitle=label("🖥 Computer",16,WHITE,true);
        windowTitle.setPadding(d(8),0,0,0);
        caption.addView(windowTitle,new LinearLayout.LayoutParams(0,d(27),1));
        Button minimize=button("—",()->window.setVisibility(View.GONE),SOFT);
        caption.addView(minimize,ll(35,26));
        Button restore=button("□",()->window.setVisibility(View.VISIBLE),SOFT);
        caption.addView(restore,ll(35,26));
        window.addView(caption,ll(-1,30));
        LinearLayout menu=row();menu.setBackgroundColor(SOFT);
        for(String name:new String[]{"File","Edit","View","Help"}){
            Button item=button(name,()->showMenu(name),SOFT);
            menu.addView(item,ll(73,28));
        }
        window.addView(menu,ll(-1,29));
        HorizontalScrollView horizontal=new HorizontalScrollView(this);
        horizontal.setHorizontalScrollBarEnabled(false);
        toolbar=row();toolbar.setPadding(d(4),d(1),d(4),d(1));toolbar.setBackgroundColor(SOFT);
        makeTool("← Back",()->history(true));
        makeTool("Forward →",()->history(false));
        makeTool("↑ Up",this::up);
        makeTool("↻ Refresh",this::refresh);
        makeTool("Copy",()->stage(false));
        makeTool("Cut",()->stage(true));
        makeTool("Paste",this::paste);
        makeTool("Rename",this::rename);
        makeTool("Delete",this::delete);
        makeTool("+ Folder",()->create(true));
        makeTool("+ File",()->create(false));
        horizontal.addView(toolbar);window.addView(horizontal,ll(-1,39));
        LinearLayout nav=row();nav.setPadding(d(7),d(3),d(7),d(3));
        nav.setBackgroundColor(0xfff0f0f0);
        currentPath=label(ROOT,13,INK,false);
        nav.addView(currentPath,new LinearLayout.LayoutParams(0,d(28),1));
        search=new EditText(this);search.setSingleLine(true);
        search.setTextSize(13);search.setHint("Search current folder");
        search.setPadding(d(7),0,d(4),0);
        search.setInputType(android.text.InputType.TYPE_CLASS_TEXT);
        // Soft keyboard requires explicit click on the search edit field.
        search.setFocusableInTouchMode(true);
        nav.addView(search,ll(190,30));
        Button find=button("Search",this::refresh,SOFT);
        nav.addView(find,ll(75,30));
        window.addView(nav,ll(-1,38));
        LinearLayout center=row();center.setGravity(Gravity.TOP);
        tree=col();tree.setPadding(d(4),d(5),d(5),d(3));
        tree.setBackgroundColor(0xfff0f5fd);
        ScrollView left=new ScrollView(this);left.setFillViewport(true);
        left.addView(tree);center.addView(left,ll(201,-1));
        View line=new View(this);line.setBackgroundColor(0xffa5b4ce);
        center.addView(line,ll(2,-1));
        LinearLayout right=col();
        LinearLayout heads=row();heads.setBackgroundColor(SOFT);
        TextView headName=label("  Name",13,INK,true);
        heads.addView(headName,new LinearLayout.LayoutParams(0,d(29),4));
        TextView headType=label("Type",13,INK,true);
        heads.addView(headType,new LinearLayout.LayoutParams(0,d(29),2));
        TextView headSize=label("Size",13,INK,true);
        heads.addView(headSize,new LinearLayout.LayoutParams(0,d(29),2));
        heads.setOnClickListener(v->{sort=(sort+1)%3;refresh();});
        right.addView(heads,ll(-1,29));
        ScrollView contents=new ScrollView(this);
        contents.setFillViewport(true);
        list=col();list.setBackgroundColor(WHITE);contents.addView(list);
        right.addView(contents,new LinearLayout.LayoutParams(-1,0,1));
        center.addView(right,new LinearLayout.LayoutParams(0,-1,1));
        window.addView(center,new LinearLayout.LayoutParams(-1,0,1));
        status=label("Ready",12,INK,false);
        status.setBackgroundColor(SOFT);status.setPadding(d(7),0,0,0);
        window.addView(status,ll(-1,26));
        taskbar=row();taskbar.setBackgroundColor(BLUE);
        Button start=button("▶ start",this::toggleStart,GREEN);
        taskbar.addView(start,ll(115,38));
        taskLabel=label("  Computer",14,WHITE,false);
        taskLabel.setOnClickListener(v->window.setVisibility(View.VISIBLE));
        taskbar.addView(taskLabel,new LinearLayout.LayoutParams(0,d(38),1));
        clock=label("",13,WHITE,false);clock.setGravity(Gravity.CENTER);
        taskbar.addView(clock,ll(105,38));
        shell.addView(taskbar,ll(-1,40));
        startMenu=col();startMenu.setPadding(d(7),d(6),d(7),d(6));
        startMenu.setBackground(bg(0xffdae8fc,7));
        startItem("Computer / drives",()->navigate(null,true));
        startItem("My Documents",()->{
            File p=Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS);
            if(allowed(p))navigate(p,true);
            else information("Documents unavailable. Grant file permission first.");
        });
        startItem("Downloads",()->{
            File p=Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if(allowed(p))navigate(p,true);
            else information("Downloads unavailable. Grant file permission first.");
        });
        startItem("Run Windows / Wine",this::launchWine);
        startItem("Native File Launcher",()->startActivity(
                new Intent(this,RM11FileLauncherActivity.class)));
        startItem("Diagnostics",()->startActivity(new Intent(this,MainActivity.class)));
        startItem("Permissions (D:)",this::askStorage);
        startItem("Exit XP shell",this::finish);
        FrameLayout.LayoutParams pop=new FrameLayout.LayoutParams(d(250),d(340),
                Gravity.BOTTOM|Gravity.LEFT);pop.bottomMargin=d(45);pop.leftMargin=d(4);
        desktop.addView(startMenu,pop);startMenu.setVisibility(View.GONE);
        updateClock();
        clock.postDelayed(new Runnable(){
            @Override public void run(){
                if(isFinishing()||isDestroyed())return;
                updateClock();clock.postDelayed(this,30000);
            }
        },30000);
        // Keep the IME hidden unless the user taps a text-edit field.
        desktop.setFocusableInTouchMode(true);desktop.requestFocus();
    }
    private void updateClock(){
        clock.setText(new java.text.SimpleDateFormat("h:mm a",Locale.US)
                .format(new java.util.Date()));
    }
    private void toggleStart(){
        showStart=!showStart;startMenu.setVisibility(showStart?View.VISIBLE:View.GONE);
    }
    private void showMenu(String kind){
        String[] names;
        Runnable[] commands;
        switch(kind){
            case "File":
                names=new String[]{"New folder","New file","Rename","Delete","Refresh"};
                commands=new Runnable[]{()->create(true),()->create(false),this::rename,this::delete,this::refresh};
                break;
            case "Edit":
                names=new String[]{"Copy","Cut","Paste"};
                commands=new Runnable[]{()->stage(false),()->stage(true),this::paste};
                break;
            case "View":
                names=new String[]{"Sort by name","Sort by size","Sort by date"};
                commands=new Runnable[]{()->{sort=0;refresh();},()->{sort=1;refresh();},
                        ()->{sort=2;refresh();}};
                break;
            default:
                names=new String[]{"About RM11 native shell"};
                commands=new Runnable[]{()->information(
                        "Android-native XP-style file manager. Wine is launched separately to protect your files if X11 fails.")};
        }
        new AlertDialog.Builder(this).setTitle(kind)
            .setItems(names,(dlg,which)->commands[which].run()).show();
    }
    private void information(String s){
        if(isFinishing())return;
        new AlertDialog.Builder(this).setMessage(s)
            .setPositiveButton("OK",null).show();
    }
    private boolean rootFile(File file){
        if(file==null)return false;
        try{
            if(Files.isSymbolicLink(file.toPath()))return false;
            File actual=file.getCanonicalFile();
            File c=layout.winePrefix.resolve("drive_c").toFile().getCanonicalFile();
            boolean safeC=actual.equals(c)||actual.toPath().startsWith(c.toPath());
            File d=Environment.getExternalStorageDirectory().getCanonicalFile();
            boolean safeD=Build.VERSION.SDK_INT>=30 && Environment.isExternalStorageManager()
                    && (actual.equals(d)||actual.toPath().startsWith(d.toPath()));
            return safeC||safeD;
        }catch(IOException|SecurityException e){return false;}
    }
    private boolean allowed(File path){
        return rootFile(path) && path.exists() && path.isDirectory();
    }
    private void askStorage(){
        try {
            Intent p=PhoneDriveBridge.permissionIntent(this);
            if(p!=null)startActivity(p);
            else startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
        }catch(Exception e){information("Storage permission settings unavailable.");}
    }
    private void launchWine(){
        // A GUI failure must not take down the native file manager.
        getSharedPreferences(XpExplorerPreviewHelper.PREFS,Context.MODE_PRIVATE)
            .edit().putBoolean(XpExplorerPreviewHelper.KEY,false).apply();
        startActivity(new Intent(this,RM11NativeWineActivity.class));
    }
    private void treeButton(String title,Runnable action,int indent){
        TextView t=label(title,13,INK,false);t.setPadding(d(indent),d(3),0,d(3));
        t.setOnClickListener(v->action.run());
        tree.addView(t,ll(-1,31));
    }
    private void redrawTree(){
        tree.removeAllViews();
        treeButton("🖥 Computer",()->navigate(null,true),2);
        File c=layout.winePrefix.resolve("drive_c").toFile();
        if(c.isDirectory())treeButton("  ▣ C: Windows",()->navigate(c,true),9);
        if(Build.VERSION.SDK_INT>=30 && Environment.isExternalStorageManager())
            treeButton("  ▣ D: Phone",()->navigate(
                Environment.getExternalStorageDirectory(),true),9);
        else treeButton("  D: (permission)",this::askStorage,9);
        if(here!=null){
            File p=here;ArrayList<File> stack=new ArrayList<>();
            for(int i=0;i<6&&p!=null&&rootFile(p);i++,p=p.getParentFile())
                stack.add(p);
            Collections.reverse(stack);
            for(File f:stack)treeButton("   ↳ "+f.getName(),()->navigate(f,true),19);
        }
    }
    private void navigate(File destination,boolean record){
        if(destination!=null&&!allowed(destination)){
            information("Cannot open this directory, or storage permission is missing.");
            return;
        }
        if(record && (here==null?destination!=null:!here.equals(destination))){
            if(back.size()>=40)back.removeFirst();
            back.addLast(here==null?new File("/__rm11_computer__"):here);
            forward.clear();
        }
        here=destination;selection=null;
        refresh();
    }
    private boolean special(File file){
        return file!=null&&file.getPath().equals("/__rm11_computer__");
    }
    private void history(boolean backwards){
        ArrayDeque<File> from=backwards?back:forward;
        if(from.isEmpty())return;
        File dest=from.removeLast();
        if(special(dest))dest=null;
        File prev=here==null?new File("/__rm11_computer__"):here;
        if((backwards?forward:back).size()>=40)(backwards?forward:back).removeFirst();
        (backwards?forward:back).addLast(prev);
        if(dest!=null&&!allowed(dest)){
            information("History folder is no longer accessible.");return;
        }
        here=dest;selection=null;refresh();
    }
    private void up(){
        if(here==null)return;
        File parent=here.getParentFile();
        if(parent==null||!rootFile(parent))navigate(null,true);
        else navigate(parent,true);
    }
    private void refresh(){
        final int g=generation.incrementAndGet();
        final File path=here;
        final int sortBy=sort;
        final String filter=search==null?"":search.getText().toString().toLowerCase(Locale.ROOT).trim();
        currentPath.setText(path==null?ROOT:path.getAbsolutePath());
        windowTitle.setText("🖥 "+(path==null?ROOT:path.getName()));
        taskLabel.setText("  "+(path==null?ROOT:path.getName()));
        status.setText("Loading...");
        if(path==null){
            ArrayList<File> drives=new ArrayList<>();
            File c=layout.winePrefix.resolve("drive_c").toFile();
            if(allowed(c))drives.add(c);
            File d=Environment.getExternalStorageDirectory();
            if(allowed(d))drives.add(d);
            render(g,drives,0,true);return;
        }
        io.execute(()->{
            File[] values=path.listFiles();
            ArrayList<File> files=new ArrayList<>();
            int hidden=0;
            if(values!=null){
                for(File v:values){
                    if(v==null||!rootFile(v)){hidden++;continue;}
                    if(!filter.isEmpty()&&!v.getName().toLowerCase(Locale.ROOT).contains(filter))
                        continue;
                    files.add(v);
                }
            }
            Comparator<File> compare=Comparator.comparing((File f)->!f.isDirectory());
            if(sortBy==1)compare=compare.thenComparingLong(File::length)
                                      .thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER);
            else if(sortBy==2)compare=compare.thenComparingLong(File::lastModified)
                                      .thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER);
            else compare=compare.thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER);
            files.sort(compare);
            int rest=files.size()>LIMIT?files.size()-LIMIT:0;
            if(rest>0)files.subList(LIMIT,files.size()).clear();
            final int omitted=hidden+rest;
            runOnUiThread(()->render(g,files,omitted,false));
        });
    }
    private void render(int expected,ArrayList<File> values,int skipped,boolean drives){
        if(isFinishing()||generation.get()!=expected)return;
        shown.clear();shown.addAll(values);
        redrawTree();
        list.removeAllViews();
        if(values.isEmpty()){
            TextView blank=label(drives?"No mounted drives":"Empty folder",15,INK,false);
            blank.setPadding(d(20),d(14),0,0);
            list.addView(blank,ll(-1,44));
        }
        for(File f:values){
            LinearLayout r=row();
            boolean selected=selection!=null&&selection.equals(f);
            r.setBackgroundColor(selected?0xffc8def9:WHITE);
            r.setPadding(d(5),d(3),d(8),d(3));
            boolean folder=f.isDirectory();
            String name=drives?(f.equals(layout.winePrefix.resolve("drive_c").toFile())
                    ?"C:": "D:") :f.getName();
            TextView nameText=label((folder?"📁 ":"📄 ")+name,13,INK,false);
            r.addView(nameText,new LinearLayout.LayoutParams(0,d(28),4));
            r.addView(label(folder?"Folder":"File",12,INK,false),
                    new LinearLayout.LayoutParams(0,d(28),2));
            r.addView(label(folder?"":formatSize(f.length()),12,INK,false),
                    new LinearLayout.LayoutParams(0,d(28),2));
            r.setOnClickListener(v->{
                if(selection!=null&&selection.equals(f)&&folder){
                    navigate(f,true);return;
                }
                if(selection!=null&&selection.equals(f)&&!folder){
                    information("Selected file: "+f.getName()+"\nUse Wine/EXE launcher to run Windows programs.");
                    return;
                }
                selection=f;refreshSelectionUI();
            });
            r.setOnLongClickListener(v->{
                selection=f;fileMenu(f);return true;
            });
            list.addView(r,ll(-1,35));
        }
        status.setText(values.size()+" item(s)"+(skipped>0?" | hidden/limited: "+skipped:"")
                        +" | "+(here==null?"Computer":here.getName()));
        hideIme();
    }
    private void refreshSelectionUI(){
        // Repaint highlight only; avoids re-enumerating directory on selection.
        for(int i=0;i<shown.size()&&i<list.getChildCount();i++){
            View v=list.getChildAt(i);v.setBackgroundColor(
                    selection!=null&&selection.equals(shown.get(i))?0xffc8def9:WHITE);
        }
    }
    private static String formatSize(long bytes){
        if(bytes<1024)return bytes+" B";
        if(bytes<1048576)return (bytes/1024)+" KB";
        if(bytes<1073741824L)return (bytes/1048576)+" MB";
        return String.format(Locale.US,"%.1f GB",bytes/1073741824.0);
    }
    private void hideIme(){
        View focus=getCurrentFocus();if(focus==search)return;
        InputMethodManager imm=(InputMethodManager)getSystemService(INPUT_METHOD_SERVICE);
        if(imm!=null)imm.hideSoftInputFromWindow(desktop.getWindowToken(),0);
    }
    private void fileMenu(File f){
        String[] opts=f.isDirectory()
            ?new String[]{"Open","Copy","Cut","Rename","Delete"}
            :new String[]{"Copy","Cut","Rename","Delete"};
        new AlertDialog.Builder(this).setTitle(f.getName())
            .setItems(opts,(dlg,which)->{
                selection=f;String op=opts[which];
                if(op.equals("Open"))navigate(f,true);
                if(op.equals("Copy"))stage(false);
                if(op.equals("Cut"))stage(true);
                if(op.equals("Rename"))rename();
                if(op.equals("Delete"))delete();
            }).show();
    }
    private void stage(boolean move){
        if(selection==null||!rootFile(selection)){
            information("Select a file or folder first.");return;
        }
        buffer=selection;cut=move;
        status.setText((cut?"Cut: ":"Copy: ")+buffer.getName());
    }
    private void paste(){
        if(buffer==null||here==null||!allowed(here)){
            information("Choose a destination folder and copy/cut a source first.");return;
        }
        File from=buffer,to=new File(here,buffer.getName());
        if(!rootFile(from)||!rootFile(to)||to.exists()){
            information("Operation blocked: missing permission or destination already exists.");
            return;
        }
        if(from.isDirectory()&&to.getAbsolutePath().startsWith(from.getAbsolutePath()+File.separator)){
            information("Cannot paste a folder into itself.");return;
        }
        io.execute(()->{
            String problem=null;
            try{
                if(cut)Files.move(from.toPath(),to.toPath());
                else copyRecursive(from.toPath(),to.toPath(),0);
            }catch(Exception e){problem=e.getClass().getSimpleName()+": "+e.getMessage();}
            final String error=problem;
            runOnUiThread(()->{
                if(error==null){if(cut)buffer=null;refresh();}
                else information("Copy/move failed: "+error);
            });
        });
    }
    private void copyRecursive(Path from,Path dest,int depth)throws IOException{
        if(depth>24)throw new IOException("Directory nesting exceeds safe limit");
        if(Files.isSymbolicLink(from)||Files.exists(dest,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Links or existing destination not allowed");
        if(Files.isDirectory(from,LinkOption.NOFOLLOW_LINKS)){
            Files.createDirectory(dest);
            try(java.nio.file.DirectoryStream<Path> stream=Files.newDirectoryStream(from)){
                for(Path child:stream){
                    if(!rootFile(child.toFile())||!rootFile(dest.resolve(child.getFileName()).toFile()))
                        throw new IOException("Directory contains inaccessible path");
                    copyRecursive(child,dest.resolve(child.getFileName()),depth+1);
                }
            }
        }else{
            Files.copy(from,dest);
        }
    }
    private void editName(String title,String proposed,java.util.function.Consumer<String> onSubmit){
        EditText input=new EditText(this);input.setSingleLine(true);
        input.setText(proposed);input.selectAll();
        new AlertDialog.Builder(this).setTitle(title).setView(input)
            .setNegativeButton("Cancel",null)
            .setPositiveButton("Save",(dlg,which)->{
                String text=input.getText().toString().trim();
                if(text.isEmpty()||text.equals(".")||text.equals("..")||
                    text.contains("/")||text.contains("\\")||text.contains("\0")){
                    information("Invalid file name.");return;
                }
                onSubmit.accept(text);
            }).show();
    }
    private void create(boolean folder){
        if(here==null||!allowed(here)){information("Open a writable folder first.");return;}
        editName(folder?"New folder":"New file",folder?"New Folder":"New File.txt",name->{
            File target=new File(here,name);
            if(!rootFile(target)||target.exists()){
                information("Invalid path or item already exists.");return;
            }
            io.execute(()->{
                String error=null;
                try{
                    if(folder)Files.createDirectory(target.toPath());
                    else Files.createFile(target.toPath());
                }catch(Exception e){error=e.getMessage();}
                String result=error;
                runOnUiThread(()->{if(result!=null)information("Create failed: "+result);refresh();});
            });
        });
    }
    private void rename(){
        File from=selection;
        if(from==null||!rootFile(from)){information("Select an item first.");return;}
        editName("Rename",from.getName(),value->{
            File to=new File(from.getParentFile(),value);
            if(!rootFile(to)||to.exists()){information("Name already exists or invalid.");return;}
            io.execute(()->{
                String error=null;
                try{Files.move(from.toPath(),to.toPath());}
                catch(Exception e){error=e.getMessage();}
                String result=error;
                runOnUiThread(()->{if(result!=null)information("Rename failed: "+result);refresh();});
            });
        });
    }
    private void delete(){
        File target=selection;
        if(target==null||!rootFile(target)){information("Select an item first.");return;}
        new AlertDialog.Builder(this).setTitle("Delete")
            .setMessage("Delete "+target.getName()+"? This is permanent. Non-empty folders are protected.")
            .setNegativeButton("Cancel",null)
            .setPositiveButton("Delete",(dialog,which)->io.execute(()->{
                String error=null;
                try{Files.delete(target.toPath());}
                catch(Exception e){error=e.getMessage();}
                String result=error;
                runOnUiThread(()->{if(result!=null)information("Delete failed: "+result);refresh();});
            })).show();
    }
    @Override public void onBackPressed(){
        if(showStart)toggleStart();
        else if(!back.isEmpty())history(true);
        else super.onBackPressed();
    }
    @Override protected void onDestroy(){
        generation.incrementAndGet();io.shutdownNow();super.onDestroy();
    }
}
