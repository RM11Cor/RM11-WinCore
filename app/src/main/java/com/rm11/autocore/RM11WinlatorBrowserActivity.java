package com.rm11.autocore;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.RuntimeLayout;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * RM11 adapter of Winlator 11.2 File Manager. Its original XML item layouts
 * and menu semantics are retained, pinned at GitHub SHA
 * 8077f374ef2d54127b088de9e8cd7b4af14d9c8b; see third_party and LGPL.
 *
 * Winlator's ContainerManager, RootFS, Box64/XServer and Wine execution are
 * NOT copied: only file manager presentation is adapted to genuine RM11 C/D.
 * Navigation never creates an X11 or Wine process and never asks for IME.
 */
public final class RM11WinlatorBrowserActivity extends AppCompatActivity {
    private final ExecutorService io=Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private final AtomicInteger refreshId=new AtomicInteger();
    private final ArrayDeque<File> pathStack=new ArrayDeque<>();
    private final BrowserAdapter adapter=new BrowserAdapter();
    private final ArrayList<Entry> entries=new ArrayList<>();
    private RuntimeLayout layout;
    private File cRoot,dRoot,selected,clipboard;
    private boolean cut,gridStyle=false;
    private RecyclerView recycler;
    private TextView location,status;
    private Button pasteButton;
    private static final int MAX_ENTRIES=10000;
    private static final int BG=0xff101925,ITEM=0xff263345,WHITE=Color.WHITE;
    private static final class Entry {
        final File file;final String title;final boolean dir;final boolean drive;
        Entry(File f,String title,boolean drive){
            file=f;this.title=title;this.drive=drive;dir=f.isDirectory();
        }
    }
    @Override public void onCreate(Bundle b){
        super.onCreate(b);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        layout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
        cRoot=layout.winePrefix.resolve("drive_c").toFile();
        dRoot=Environment.getExternalStorageDirectory();
        buildView();
        reload();
    }
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private LinearLayout row(){
        LinearLayout line=new LinearLayout(this);line.setOrientation(0);
        line.setGravity(Gravity.CENTER_VERTICAL);
        line.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        return line;
    }
    private TextView text(String s,int size){
        TextView label=new TextView(this);
        label.setText(s);label.setTextSize(size);label.setTextColor(WHITE);
        label.setGravity(Gravity.CENTER_VERTICAL);label.setSingleLine(true);
        return label;
    }
    private Button addButton(LinearLayout parent,String caption,Runnable command){
        Button button=new Button(this);button.setText(caption);button.setAllCaps(false);
        button.setTextSize(12);button.setOnClickListener(v->command.run());
        parent.addView(button,new LinearLayout.LayoutParams(dp(108),dp(40)));
        button.setFocusableInTouchMode(false);return button;
    }
    private void buildView(){
        LinearLayout page=new LinearLayout(this);page.setOrientation(1);
        page.setBackgroundColor(BG);
        setContentView(page);
        LinearLayout bar=row();bar.setBackgroundColor(0xff1a3153);
        addButton(bar,"← Back",this::back);
        addButton(bar,"Computer",()->{pathStack.clear();reload();});
        location=text("Computer",15);
        location.setPadding(dp(8),0,0,0);
        bar.addView(location,new LinearLayout.LayoutParams(0,dp(43),1));
        addButton(bar,"↻ Refresh",this::reload);
        addButton(bar,"List / Grid",()->{gridStyle=!gridStyle;layoutMode();});
        page.addView(bar,new LinearLayout.LayoutParams(-1,dp(48)));
        LinearLayout commands=row();commands.setBackgroundColor(0xff17283e);
        addButton(commands,"New Folder",()->create(true));
        addButton(commands,"New File",()->create(false));
        pasteButton=addButton(commands,"Paste",this::paste);
        pasteButton.setEnabled(false);
        addButton(commands,"Windows/Wine",()->startActivity(
                new Intent(this,RM11NativeWineActivity.class)));
        page.addView(commands,new LinearLayout.LayoutParams(-1,dp(43)));
        recycler=new RecyclerView(this);
        recycler.setHasFixedSize(false);recycler.setAdapter(adapter);
        page.addView(recycler,new LinearLayout.LayoutParams(-1,0,1));
        layoutMode();
        status=text("Ready",12);status.setPadding(dp(12),0,0,0);
        status.setBackgroundColor(0xff17283e);
        page.addView(status,new LinearLayout.LayoutParams(-1,dp(30)));
        page.setFocusableInTouchMode(true);page.requestFocus();
    }
    private void layoutMode(){
        if(recycler==null)return;
        recycler.setLayoutManager(gridStyle
                ?new GridLayoutManager(this,Math.max(2,Math.min(6,
                    getResources().getDisplayMetrics().widthPixels/dp(200))))
                :new LinearLayoutManager(this));
        recycler.setAdapter(adapter);
    }
    private File here(){return pathStack.peekLast();}
    private boolean inRoot(File candidate,File root){
        try{
            if(candidate==null||root==null||
                Files.isSymbolicLink(candidate.toPath()))return false;
            Path actual=candidate.getCanonicalFile().toPath();
            Path base=root.getCanonicalFile().toPath();
            return actual.equals(base)||actual.startsWith(base);
        }catch(IOException|SecurityException ex){return false;}
    }
    private boolean allowed(File file){
        if(inRoot(file,cRoot))return true;
        return PhoneDriveBridge.authorized()&&inRoot(file,dRoot);
    }
    private void alert(String text){
        if(isFinishing()||isDestroyed())return;
        new AlertDialog.Builder(this).setTitle("RM11 / Winlator File Manager")
                .setMessage(text).setPositiveButton("OK",null).show();
    }
    private void open(Entry e){
        if(!e.dir){select(e.file);return;}
        if(!allowed(e.file)||!e.file.isDirectory()){
            alert("Folder unavailable or storage access not granted");return;
        }
        if(pathStack.size()>45){alert("Navigation history limit reached");return;}
        pathStack.addLast(e.file);
        selected=null;reload();
    }
    private void back(){
        if(!pathStack.isEmpty())pathStack.removeLast();
        selected=null;reload();
    }
    private void requestD(){
        try{
            Intent i=PhoneDriveBridge.permissionIntent(this);
            if(i!=null)startActivity(i);
            else alert("D: access needs Android file permission");
        }catch(RuntimeException ex){alert("Unable to open file permission settings");}
    }
    @Override protected void onResume(){super.onResume();if(recycler!=null)reload();}
    private void reload(){
        final int job=refreshId.incrementAndGet();
        File folder=here();
        location.setText(folder==null?"Computer":folder.getAbsolutePath());
        status.setText("Reading files...");
        if(folder==null){
            ArrayList<Entry> roots=new ArrayList<>();
            if(cRoot.isDirectory())roots.add(new Entry(cRoot,"Windows (C:)",true));
            if(PhoneDriveBridge.authorized())roots.add(new Entry(dRoot,"Phone (D:)",true));
            else roots.add(new Entry(dRoot,"D: — permission required",true));
            update(job,roots,"Available drives");return;
        }
        io.execute(()->{
            ArrayList<Entry> found=new ArrayList<>();
            String message;
            if(!allowed(folder)||!folder.isDirectory()){
                message="Access denied or folder is unavailable";
            }else{
                File[] children=folder.listFiles();
                if(children==null){message="Folder cannot be read";}
                else{
                    Arrays.sort(children,Comparator.comparing((File f)->!f.isDirectory())
                        .thenComparing(File::getName,String.CASE_INSENSITIVE_ORDER));
                    int total=0;
                    for(File child:children){
                        if(!allowed(child))continue;
                        total++;
                        if(found.size()<MAX_ENTRIES)
                            found.add(new Entry(child,child.getName(),false));
                    }
                    message=total+" items"+(total>MAX_ENTRIES?" (first 10,000 shown)":"");
                }
            }
            String finalMsg=message;
            main.post(()->update(job,found,finalMsg));
        });
    }
    private void update(int job,ArrayList<Entry> found,String info){
        if(refreshId.get()!=job||isFinishing())return;
        entries.clear();entries.addAll(found);
        adapter.notifyDataSetChanged();
        status.setText(info);
        pasteButton.setEnabled(clipboard!=null&&here()!=null);
    }
    private void select(File f){selected=f;adapter.notifyDataSetChanged();}
    private String formattedSize(long v){
        if(v<1024)return v+" B";
        if(v<1048576)return v/1024+" KB";
        if(v<1073741824L)return v/1048576+" MB";
        return String.format(Locale.US,"%.1f GB",v/1073741824.0);
    }
    private void menu(View anchor,Entry item){
        PopupMenu menu=new PopupMenu(this,anchor);
        if(item.dir)menu.getMenu().add("Open").setOnMenuItemClickListener(m->{
            if(!allowed(item.file)&&item.file.equals(dRoot))requestD();else open(item);return true;
        });
        if(!item.drive && allowed(item.file)){
            menu.getMenu().add("Copy").setOnMenuItemClickListener(m->{
                clipboard=item.file;cut=false;selected=item.file;pasteButton.setEnabled(true);return true;
            });
            menu.getMenu().add("Cut").setOnMenuItemClickListener(m->{
                clipboard=item.file;cut=true;selected=item.file;pasteButton.setEnabled(true);return true;
            });
            menu.getMenu().add("Rename").setOnMenuItemClickListener(m->{
                rename(item.file);return true;
            });
            menu.getMenu().add("Delete").setOnMenuItemClickListener(m->{
                remove(item.file);return true;
            });
        }
        menu.getMenu().add("Information").setOnMenuItemClickListener(m->{
            alert(item.title+"\n"+item.file.getAbsolutePath()+
                "\n"+(item.dir?"Folder":formattedSize(item.file.length())));return true;
        });
        menu.show();
    }
    private void filenamePrompt(String title,String value,java.util.function.Consumer<String> done){
        EditText input=new EditText(this);input.setSingleLine(true);input.setText(value);
        input.setSelectAllOnFocus(true);
        // Keyboard is only allowed for intentionally selected text entry.
        new AlertDialog.Builder(this).setTitle(title).setView(input)
                .setNegativeButton("Cancel",null)
                .setPositiveButton("Save",(dialog,which)->{
                    String name=input.getText().toString().trim();
                    if(name.isEmpty()||name.equals(".")||name.equals("..")||
                        name.contains("/")||name.contains("\\")||name.indexOf('\0')>=0){
                        alert("Invalid name");return;
                    }
                    done.accept(name);
                }).show();
    }
    private void create(boolean directory){
        File p=here();
        if(p==null||!allowed(p)){alert("Open C: or permitted D: first");return;}
        filenamePrompt(directory?"New Folder":"New File",
                directory?"New Folder":"New File.txt",name->{
            File target=new File(p,name);
            if(!allowed(target)||target.exists()){alert("Destination exists or denied");return;}
            io.execute(()->{
                String error=null;
                try{if(directory)Files.createDirectory(target.toPath());
                    else Files.createFile(target.toPath());}
                catch(Exception e){error=e.getClass().getSimpleName();}
                String msg=error;main.post(()->{if(msg!=null)alert("Create: "+msg);reload();});
            });
        });
    }
    private void rename(File source){
        if(source==null||!allowed(source)){alert("Invalid selection");return;}
        filenamePrompt("Rename",source.getName(),name->{
            File target=new File(source.getParentFile(),name);
            if(!allowed(target)||target.exists()){alert("Destination exists or denied");return;}
            io.execute(()->{
                String error=null;
                try{Files.move(source.toPath(),target.toPath());}
                catch(Exception ex){error=ex.getClass().getSimpleName();}
                String msg=error;main.post(()->{if(msg!=null)alert("Rename: "+msg);reload();});
            });
        });
    }
    private void remove(File item){
        if(!allowed(item))return;
        new AlertDialog.Builder(this).setTitle("Confirm delete")
            .setMessage("Delete "+item.getName()+"? Nonempty directories are protected.")
            .setNegativeButton("Cancel",null)
            .setPositiveButton("Delete",(dialog,which)->io.execute(()->{
                String error=null;
                try{Files.delete(item.toPath());}
                catch(Exception ex){error=ex.getClass().getSimpleName();}
                String msg=error;main.post(()->{if(msg!=null)alert("Delete: "+msg);reload();});
            })).show();
    }
    private void paste(){
        File target=here(),origin=clipboard;
        if(target==null||origin==null||!allowed(target)||!allowed(origin)){
            alert("Select a source and a valid destination folder");return;
        }
        File dest=new File(target,origin.getName());
        if(!allowed(dest)||dest.exists()){alert("Destination exists or denied");return;}
        try{
            if(origin.isDirectory()&&dest.getCanonicalPath().startsWith(
                    origin.getCanonicalPath()+File.separator)){
                alert("Cannot copy a folder into itself");return;
            }
        }catch(IOException e){alert("Invalid path");return;}
        final boolean move=cut;
        io.execute(()->{
            String failure=null;
            try{
                if(move)Files.move(origin.toPath(),dest.toPath());
                else copySafely(origin.toPath(),dest.toPath(),0,new int[]{0});
            }catch(Exception ex){failure=ex.getClass().getSimpleName()+": "+ex.getMessage();}
            String msg=failure;
            main.post(()->{
                if(msg==null){if(move){clipboard=null;cut=false;}reload();}
                else alert("Paste failed: "+msg);
            });
        });
    }
    private void copySafely(Path from,Path to,int depth,int[] count)throws IOException{
        if(depth>24||++count[0]>5000)throw new IOException("Safety limit on recursive copy");
        if(Files.isSymbolicLink(from)||Files.exists(to,LinkOption.NOFOLLOW_LINKS)||
                !allowed(from.toFile())||!allowed(to.toFile()))
            throw new IOException("Unsafe path, symlink or existing destination");
        if(Files.isDirectory(from,LinkOption.NOFOLLOW_LINKS)){
            Files.createDirectory(to);
            try(java.nio.file.DirectoryStream<Path> scan=Files.newDirectoryStream(from)){
                for(Path child:scan)copySafely(child,to.resolve(child.getFileName()),depth+1,count);
            }
        }else Files.copy(from,to);
    }
    private final class BrowserAdapter extends RecyclerView.Adapter<BrowserAdapter.Holder>{
        private final class Holder extends RecyclerView.ViewHolder{
            final ImageView icon,run,options;
            final TextView name,detail;
            Holder(View v){
                super(v);
                icon=v.findViewById(R.id.ImageView);
                name=v.findViewById(R.id.TVTitle);
                detail=v.findViewById(R.id.TVSubtitle);
                run=v.findViewById(R.id.BTRun);
                options=v.findViewById(R.id.BTMenu);
            }
        }
        @NonNull @Override public Holder onCreateViewHolder(@NonNull android.view.ViewGroup p,int type){
            int id=gridStyle?R.layout.file_grid_item:R.layout.file_list_item;
            return new Holder(getLayoutInflater().inflate(id,p,false));
        }
        @Override public void onBindViewHolder(@NonNull Holder holder,int position){
            Entry item=entries.get(position);
            holder.name.setText(item.title);
            holder.detail.setText(item.drive?"Drive":item.dir?"Folder":formattedSize(item.file.length()));
            holder.detail.setVisibility(View.VISIBLE);
            holder.icon.setImageResource(item.dir?android.R.drawable.ic_menu_agenda:android.R.drawable.ic_menu_save);
            holder.run.setImageResource(item.dir?android.R.drawable.ic_menu_directions:android.R.drawable.ic_menu_info_details);
            holder.icon.setOnClickListener(v->{
                if(item.drive&&!allowed(item.file)){requestD();return;}open(item);
            });
            holder.run.setOnClickListener(v->{
                if(item.drive&&!allowed(item.file)){requestD();return;}open(item);
            });
            holder.name.setOnClickListener(v->{
                if(item.dir){
                    if(item.drive&&!allowed(item.file))requestD();else open(item);
                }else select(item.file);
            });
            holder.options.setOnClickListener(v->menu(v,item));
            holder.itemView.setOnClickListener(v->{
                if(item.dir){
                    if(item.drive&&!allowed(item.file))requestD();else open(item);
                }else select(item.file);
            });
            holder.itemView.setBackgroundColor(item.file.equals(selected)?ITEM:Color.TRANSPARENT);
        }
        @Override public int getItemCount(){return entries.size();}
    }
    @Override public void onBackPressed(){
        if(pathStack.isEmpty())super.onBackPressed();
        else back();
    }
    @Override protected void onDestroy(){refreshId.incrementAndGet();io.shutdownNow();super.onDestroy();}
}
