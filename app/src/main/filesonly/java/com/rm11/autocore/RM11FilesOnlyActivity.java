package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.database.Cursor;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.graphics.Insets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Locale;

/**
 * v4.0.47 cleanup: THE ONLY application screen.
 * No Wine, wineserver, X11, Nova desktop, intro, other activities, native code,
 * executable launcher, or background runtime startup is linked or invoked.
 * Existing app data, old Wine prefix and previously selected SAF phone folder
 * are left intact. Never erase app storage during an in-place update.
 */
public final class RM11FilesOnlyActivity extends Activity {
    private static final int PICK_PHONE=9471;
    private static final int BG=0xff090d15;
    private static final int PANEL=0xff171e2a;
    private static final int ITEM=0xff1b2432;
    private static final int WHITE=0xfff5f6f9;
    private static final int MUTED=0xff9da9ba;
    private static final int RED=0xfff04452;
    private static final int EDGE=0xff343948;
    private static final String SAVED_PHONE="rm11_files_only_phone_uri";
    private final ArrayDeque<Location> history=new ArrayDeque<>();
    private File home;
    private File workspace;
    private Uri phoneTree;
    private LinearLayout entries;
    private TextView heading,crumb,status;
    private int displayed;

    private static final class Location {
        final File local;
        final String documentId;
        final String title;
        Location(File root,String title) { this.local=root;this.documentId=null;this.title=title; }
        Location(String documentId,String title) { this.local=null;this.documentId=documentId;this.title=title; }
    }

    private int d(float dp){return (int)(getResources().getDisplayMetrics().density*dp+.5f);}
    private GradientDrawable background(int color,int radius){
        GradientDrawable value=new GradientDrawable();
        value.setColor(color);
        value.setCornerRadius(d(radius));
        value.setStroke(d(1),EDGE);
        return value;
    }
    private TextView label(String title,int sp,int color,boolean bold){
        TextView value=new TextView(this);
        value.setText(title);
        value.setTextColor(color);
        value.setTextSize(sp);
        value.setGravity(Gravity.CENTER_VERTICAL);
        value.setTypeface(Typeface.create("sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));
        return value;
    }
    private Button button(String title,Runnable action){
        Button value=new Button(this);
        value.setText(title);
        value.setAllCaps(false);
        value.setTextColor(WHITE);
        value.setTextSize(13);
        value.setPadding(d(8),0,d(8),0);
        value.setMinimumHeight(0);
        value.setMinHeight(0);
        value.setBackground(background(PANEL,8));
        value.setOnClickListener(v->action.run());
        return value;
    }
    private LinearLayout horizontal(){
        LinearLayout l=new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        l.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        return l;
    }
    private LinearLayout vertical(){
        LinearLayout l=new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }
    private LinearLayout.LayoutParams p(int width,int height){
        return new LinearLayout.LayoutParams(width<0?width:d(width),height<0?height:d(height));
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN);
        if(Build.VERSION.SDK_INT>=30)getWindow().setDecorFitsSystemWindows(false);
        home=getFilesDir();
        workspace=new File(home,"nova-workspace");
        // Old files are PRESERVED, not migrated/deleted.
        if(!workspace.exists())workspace.mkdirs();
        String saved=getPreferences(0).getString(SAVED_PHONE,null);
        if(saved==null) {
            // The previous file manager stored a persisted SAF folder here.
            saved=getSharedPreferences("RM11FileLauncherActivity",MODE_PRIVATE)
                    .getString("rm11_selected_tree",null);
        }
        if(saved!=null)try{phoneTree=Uri.parse(saved);}catch(RuntimeException ignored){}
        createScreen();
        navigate(new Location(home,"ملفات التطبيق"));
    }
    private void createScreen(){
        LinearLayout root=vertical();
        root.setBackgroundColor(BG);
        root.setPadding(d(14),d(9),d(14),d(9));
        if(Build.VERSION.SDK_INT>=30){
            root.setOnApplyWindowInsetsListener((v,insets)->{
                Insets b=insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout());
                v.setPadding(d(14)+b.left,d(9)+b.top,d(14)+b.right,d(9)+b.bottom);
                return insets;
            });
        }
        LinearLayout top=horizontal();
        TextView title=label("RM11  /  FILE MANAGER",22,WHITE,true);
        top.addView(title,new LinearLayout.LayoutParams(0,d(51),1));
        TextView simple=label("FILES ONLY  ●",12,RED,true);
        simple.setGravity(Gravity.RIGHT|Gravity.CENTER_VERTICAL);
        top.addView(simple,p(125,51));
        root.addView(top,p(-1,56));

        LinearLayout layout=horizontal();
        layout.setGravity(Gravity.TOP);
        LinearLayout rail=vertical();
        rail.setPadding(d(9),d(12),d(9),d(9));
        rail.setBackground(background(PANEL,10));
        rail.addView(label("◈  مواقع الملفات",14,RED,true),p(-1,36));
        rail.addView(button("▣  ملفات التطبيق",()->navigate(new Location(home,"ملفات التطبيق"))),spaced(0,44,7));
        rail.addView(button("◈  مساحة الملفات",()->navigate(new Location(workspace,"مساحة الملفات"))),spaced(0,44,7));
        rail.addView(button("▤  ملفات الهاتف",this::openSavedPhone),spaced(0,44,7));
        rail.addView(button("▤  اختيار مجلد من الهاتف",this::pickPhone),spaced(0,44,7));
        TextView info=label("واجهة واحدة للتصفح فقط\nبدون Windows أو سطح مكتب إضافي",11,MUTED,false);
        info.setPadding(d(5),d(16),0,0);
        rail.addView(info,p(-1,66));
        ScrollView railScroll=new ScrollView(this);
        railScroll.setFillViewport(true);
        railScroll.addView(rail);
        layout.addView(railScroll,p(235,-1));

        LinearLayout body=vertical();
        body.setPadding(d(14),0,0,0);
        heading=label("ملفات التطبيق",19,WHITE,true);
        body.addView(heading,p(-1,44));
        LinearLayout toolbar=horizontal();
        toolbar.setPadding(d(5),d(4),d(5),d(4));
        toolbar.setBackground(background(PANEL,9));
        toolbar.addView(button("← رجوع",this::backFolder),p(90,38));
        toolbar.addView(button("↻ تحديث",this::showCurrent),p(90,38));
        crumb=label("",12,MUTED,false);
        crumb.setSingleLine(true);
        crumb.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        crumb.setPadding(d(10),0,0,0);
        toolbar.addView(crumb,new LinearLayout.LayoutParams(0,d(39),1));
        body.addView(toolbar,p(-1,49));

        LinearLayout tools=horizontal();
        tools.addView(button("+ مجلد",()->createItem(true)),p(89,38));
        tools.addView(button("+ ملف",()->createItem(false)),p(89,38));
        TextView readOnly=label("التعديل داخل مساحة الملفات فقط",11,MUTED,false);
        readOnly.setPadding(d(12),0,0,0);
        tools.addView(readOnly,new LinearLayout.LayoutParams(0,d(38),1));
        body.addView(tools,spaced(-1,44,7));

        ScrollView fileScroll=new ScrollView(this);
        fileScroll.setFillViewport(true);
        fileScroll.setBackground(background(0xff101723,10));
        entries=vertical();
        entries.setPadding(d(9),d(10),d(9),d(10));
        fileScroll.addView(entries);
        body.addView(fileScroll,new LinearLayout.LayoutParams(-1,0,1));
        status=label("جاهز — ملفاتك الأصلية محفوظة",11,MUTED,false);
        status.setPadding(d(6),0,0,0);
        body.addView(status,p(-1,32));
        layout.addView(body,new LinearLayout.LayoutParams(0,-1,1));
        root.addView(layout,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(root);
        if(Build.VERSION.SDK_INT>=30)root.requestApplyInsets();
    }
    private LinearLayout.LayoutParams spaced(int width,int height,int bottom){
        LinearLayout.LayoutParams out=p(width,height);
        out.bottomMargin=d(bottom);
        return out;
    }
    private boolean appPath(File path){
        try{
            String root=home.getCanonicalPath(),candidate=path.getCanonicalPath();
            return candidate.equals(root)||candidate.startsWith(root+File.separator);
        }catch(IOException e){return false;}
    }
    private boolean workspacePath(File path){
        try{
            String root=workspace.getCanonicalPath(),candidate=path.getCanonicalPath();
            return candidate.equals(root)||candidate.startsWith(root+File.separator);
        }catch(IOException e){return false;}
    }
    private void navigate(Location where){
        history.clear();
        history.push(where);
        showCurrent();
    }
    private void enter(Location where){
        history.push(where);
        showCurrent();
    }
    private void backFolder(){
        if(history.size()>1){history.pop();showCurrent();}
        else status.setText("أنت ببداية الموقع. اختار موقع من القائمة.");
    }
    @Override public void onBackPressed(){
        if(history.size()>1)backFolder();
        else super.onBackPressed();
    }
    private String fileSize(long bytes){
        if(bytes<1024)return bytes+" B";
        if(bytes<1024*1024)return(bytes/1024)+" KB";
        if(bytes<1024L*1024*1024)return(bytes/(1024*1024))+" MB";
        return String.format(Locale.ROOT,"%.1f GB",bytes/(1024.0*1024*1024));
    }
    private void row(String title,boolean folder,long size,Runnable click,Runnable longClick){
        LinearLayout item=horizontal();
        item.setPadding(d(10),d(4),d(10),d(4));
        item.setBackground(background(ITEM,7));
        TextView ico=label(folder?"▣":"▤",21,folder?RED:MUTED,true);
        ico.setGravity(Gravity.CENTER);
        item.addView(ico,p(41,46));
        LinearLayout names=vertical();
        TextView text=label(title,15,WHITE,true);
        text.setSingleLine(true);
        text.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        names.addView(text,p(-1,27));
        names.addView(label(folder?"مجلد":fileSize(size),11,MUTED,false),p(-1,19));
        item.addView(names,new LinearLayout.LayoutParams(0,d(46),1));
        item.addView(label("›",19,RED,true),p(22,46));
        item.setOnClickListener(v->click.run());
        if(longClick!=null)item.setOnLongClickListener(v->{longClick.run();return true;});
        entries.addView(item,spaced(-1,55,5));
    }
    private void showCurrent(){
        if(entries==null)return;
        entries.removeAllViews();
        Location current=history.peek();
        if(current==null)return;
        heading.setText(current.title);
        StringBuilder path=new StringBuilder();
        for(Iterator<Location> it=history.descendingIterator();it.hasNext();){
            if(path.length()>0)path.append("  /  ");
            path.append(it.next().title);
        }
        crumb.setText(path.toString());
        displayed=0;
        if(current.local!=null)showAppFiles(current);
        else showPhoneChildren(current);
    }
    private void showAppFiles(Location where){
        File dir=where.local;
        if(!appPath(dir)||!dir.isDirectory()){
            status.setText("هذا المسار غير متاح داخل مساحة التطبيق.");return;
        }
        File[] files=dir.listFiles();
        if(files==null){status.setText("تعذر قراءة المجلد.");return;}
        Arrays.sort(files,Comparator.comparing((File f)->!f.isDirectory())
                .thenComparing(f->f.getName().toLowerCase(Locale.ROOT)));
        for(File file:files){
            if(displayed>=240)break;
            if(!appPath(file))continue;
            if(file.isDirectory())
                row(file.getName(),true,0,()->enter(new Location(file,file.getName())),
                        ()->showAppDetails(file));
            else if(file.isFile())
                row(file.getName(),false,file.length(),()->showAppDetails(file),
                        ()->showAppDetails(file));
            displayed++;
        }
        if(displayed==0)entries.addView(label("هذا المجلد فارغ.",17,MUTED,false),p(-1,52));
        status.setText("ملفات التطبيق: "+displayed+" عنصر"+
                (files.length>240?" — عرض أول 240 عنصراً":"")+
                " • ماكو حذف تلقائي للملفات.");
    }
    private void showAppDetails(File file){
        new AlertDialog.Builder(this).setTitle(file.getName())
                .setMessage("المسار: "+file.getAbsolutePath()+"\nالحجم: "+fileSize(Math.max(0,file.length()))
                        +"\n\nملفات التطبيق محفوظة. لا يتم تشغيل EXE أو Windows من هنا.")
                .setPositiveButton("إغلاق",null).show();
    }
    private void pickPhone(){
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try{startActivityForResult(intent,PICK_PHONE);}
        catch(RuntimeException e){status.setText("اختيار مجلد الهاتف غير مدعوم بالجهاز.");}
    }
    private void openSavedPhone(){
        if(phoneTree==null){pickPhone();return;}
        try{navigate(new Location(DocumentsContract.getTreeDocumentId(phoneTree),
                "ملفات الهاتف"));}
        catch(RuntimeException ex){status.setText("مجلد الهاتف السابق غير متاح. اختار مجلداً جديداً.");}
    }
    private void showPhoneChildren(Location where){
        if(phoneTree==null){status.setText("اختار مجلد الهاتف أولاً.");return;}
        Uri target;
        try{target=DocumentsContract.buildChildDocumentsUriUsingTree(phoneTree,where.documentId);}
        catch(RuntimeException e){status.setText("المجلد المحدد غير صالح.");return;}
        String[] projection={DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE};
        try(Cursor data=getContentResolver().query(target,projection,null,null,null)){
            if(data==null){status.setText("التطبيق لم يحصل على صلاحية قراءة المجلد.");return;}
            int id=data.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID);
            int name=data.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME);
            int mime=data.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE);
            int size=data.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE);
            while(data.moveToNext()&&displayed<240){
                final String child=data.getString(id);
                final String nameValue=data.getString(name);
                final boolean folder=DocumentsContract.Document.MIME_TYPE_DIR.equals(data.getString(mime));
                final long bytes=size<0||data.isNull(size)?0:data.getLong(size);
                if(folder)row(nameValue,true,0,
                        ()->enter(new Location(child,nameValue)),null);
                else row(nameValue,false,bytes,
                        ()->new AlertDialog.Builder(this).setTitle(nameValue)
                            .setMessage("الحجم: "+fileSize(bytes)
                                +"\nهذا الملف موجود بذاكرة الهاتف. لم يتغيّر مكانه.")
                            .setPositiveButton("إغلاق",null).show(),null);
                displayed++;
            }
            if(displayed==0)entries.addView(label("هذا المجلد فارغ.",17,MUTED,false),p(-1,52));
            status.setText("ملفات الهاتف: "+displayed+" عنصر (قراءة فقط)"+
                    (displayed>=240?" — عرض أول 240 عنصراً":""));
        }catch(Exception failure){
            status.setText("تعذر عرض ملفات الهاتف. اختار المجلد مرة ثانية.");
        }
    }
    private void createItem(boolean folder){
        Location where=history.peek();
        if(where==null||where.local==null||!workspacePath(where.local)||!where.local.isDirectory()){
            status.setText("إنشاء الملفات متاح فقط داخل «مساحة الملفات» لحماية بقية بيانات التطبيق.");
            return;
        }
        EditText input=new EditText(this);
        input.setSingleLine(true);
        input.setText(folder?"New Folder":"New File.txt");
        new AlertDialog.Builder(this).setTitle(folder?"مجلد جديد":"ملف جديد")
            .setView(input).setNegativeButton("إلغاء",null)
            .setPositiveButton("إنشاء",(dialog,button)->{
                String name=input.getText().toString().trim();
                if(name.isEmpty()||name.equals(".")||name.equals("..")||
                        name.length()>180||name.contains("/")||name.contains("\\")||
                        name.indexOf('\0')>=0){
                    status.setText("اسم الملف غير صالح.");return;
                }
                try{
                    File target=new File(where.local,name);
                    if(!workspacePath(target)||target.exists()){
                        status.setText("هذا الاسم موجود أو خارج مساحة الملفات.");return;
                    }
                    if(folder?!target.mkdir():!target.createNewFile())
                        throw new IOException("Create failed");
                    showCurrent();
                }catch(IOException problem){
                    status.setText("تعذر إنشاء الملف أو المجلد.");
                }
            }).show();
    }
    @Override protected void onActivityResult(int code,int result,Intent data){
        super.onActivityResult(code,result,data);
        if(code==PICK_PHONE&&result==RESULT_OK&&data!=null&&data.getData()!=null){
            Uri uri=data.getData();
            try{
                getContentResolver().takePersistableUriPermission(
                        uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);
                phoneTree=uri;
                getPreferences(0).edit().putString(SAVED_PHONE,uri.toString()).apply();
                openSavedPhone();
            }catch(SecurityException e){
                status.setText("صلاحية مجلد الهاتف غير متاحة.");
            }
        }
    }
}
