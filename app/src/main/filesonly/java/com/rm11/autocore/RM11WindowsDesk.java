package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.provider.DocumentsContract;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.DateFormat;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.Locale;

/**
 * v4.0.49. This is a native Android Windows-style workspace, not Windows/Wine.
 * It intentionally launches inside the existing SINGLE Android Activity.
 * Drive letters are navigation shortcuts: C app-private RO, W workspace RW,
 * D user-selected Android SAF tree RO. It never accesses root or starts EXE.
 */
final class RM11WindowsDesk {
    private static final int BG=0xff0a1120,PANEL=0xff182438,ITEM=0xff223249;
    private static final int WHITE=0xfff3f6fc,MUTED=0xffa8bbd1,ACCENT=0xff63c1fa,LINE=0xff37465c;
    private static final int PC=0,APP=1,WORK=2,PHONE=3,TRASH=4;
    private final Activity activity;
    private final File appDir,workspace,recycle;
    private final Runnable closeDesktop,pickPhone;
    private final SharedPreferences pref;
    private Uri phoneTree;
    private FrameLayout root,stage,startPanel;
    private LinearLayout window,list;
    private TextView caption,pathLabel,status;
    private EditText search;
    private Node current;
    private final ArrayDeque<Node> back=new ArrayDeque<>(),forward=new ArrayDeque<>();
    private File copied;
    private boolean compact;

    private static final class Node {
        final int type;final File file;final String doc,title;
        Node(int t,File f,String doc,String title){this.type=t;this.file=f;this.doc=doc;this.title=title;}
    }
    RM11WindowsDesk(Activity host,File appDir,File workspace,Uri tree,
                    Runnable close,Runnable picker){
        activity=host;this.appDir=appDir;this.workspace=workspace;
        recycle=new File(workspace,".rm11-recycle");
        phoneTree=tree;closeDesktop=close;pickPhone=picker;
        pref=host.getSharedPreferences("rm11_windows_workspace",Context.MODE_PRIVATE);
        compact=pref.getBoolean("compact",false);
        if(!workspace.isDirectory())workspace.mkdirs();
        if(!recycle.isDirectory())recycle.mkdirs();
    }
    private int d(float n){return (int)(n*activity.getResources().getDisplayMetrics().density+.5f);}
    private LinearLayout v(){LinearLayout x=new LinearLayout(activity);x.setOrientation(1);return x;}
    private LinearLayout h(){LinearLayout x=new LinearLayout(activity);x.setOrientation(0);
        x.setGravity(Gravity.CENTER_VERTICAL);x.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);return x;}
    private LinearLayout.LayoutParams lp(int w,int ht){
        return new LinearLayout.LayoutParams(w<0?w:d(w),ht<0?ht:d(ht));
    }
    private GradientDrawable shape(int color,int rad){
        GradientDrawable x=new GradientDrawable();x.setColor(color);
        x.setCornerRadius(d(rad));x.setStroke(d(1),LINE);return x;
    }
    private TextView text(String str,int sp,int color,boolean bold){
        TextView x=new TextView(activity);x.setText(str);x.setTextSize(sp);
        x.setTextColor(color);x.setGravity(Gravity.CENTER_VERTICAL);
        x.setTypeface(Typeface.create("sans-serif",bold?Typeface.BOLD:Typeface.NORMAL));
        return x;
    }
    private Button btn(String label,Runnable action){
        Button b=new Button(activity);b.setText(label);b.setAllCaps(false);
        b.setTextColor(WHITE);b.setTextSize(12);b.setPadding(d(5),0,d(5),0);
        b.setMinimumHeight(0);b.setMinHeight(0);b.setMinimumWidth(0);b.setMinWidth(0);
        b.setBackground(shape(ITEM,7));b.setOnClickListener(w->action.run());return b;
    }
    private void add(LinearLayout parent,View child,int width,int height){parent.addView(child,lp(width,height));}
    private void action(LinearLayout row,String text,int width,Runnable work){add(row,btn(text,work),width,38);}
    private void alert(String message){android.widget.Toast.makeText(activity,message,android.widget.Toast.LENGTH_SHORT).show();}
    private Node pc(){return new Node(PC,null,null,"هذا الكمبيوتر");}
    private Node app(){return new Node(APP,appDir,null,"C: ملفات التطبيق");}
    private Node work(){return new Node(WORK,workspace,null,"W: مساحة العمل");}
    private Node trash(){return new Node(TRASH,recycle,null,"سلة المحذوفات");}
    private Node phone(){
        if(phoneTree==null)return null;
        try{return new Node(PHONE,null,DocumentsContract.getTreeDocumentId(phoneTree),"D: الهاتف");}
        catch(RuntimeException e){return null;}
    }
    private boolean in(File base,File candidate){
        try{String p=base.getCanonicalPath(),c=candidate.getCanonicalPath();
            return c.equals(p)||c.startsWith(p+File.separator);
        }catch(IOException e){return false;}
    }
    private boolean writable(){return current!=null&&current.type==WORK&&current.file!=null
            &&in(workspace,current.file)&&!in(recycle,current.file);}
    void show(){
        root=new FrameLayout(activity);
        root.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{0xff070e1e,0xff0f2943,0xff19243b,0xff321c36}));
        LinearLayout desktop=v();root.addView(desktop,new FrameLayout.LayoutParams(-1,-1));
        LinearLayout header=h();header.setPadding(d(20),0,d(20),0);
        TextView brand=text("⊞  RM11  /  WINDOWS WORKSPACE",19,WHITE,true);
        header.addView(brand,new LinearLayout.LayoutParams(0,-1,1));
        add(header,text("NATIVE DESKTOP • FILES & TOOLS",11,ACCENT,false),235,-1);
        add(desktop,header,-1,55);
        LinearLayout icons=h();icons.setPadding(d(20),d(4),d(20),d(7));
        desktopIcon(icons,"▣","هذا الكمبيوتر",this::openComputer);
        desktopIcon(icons,"▤","المستكشف",()->open(work()));
        desktopIcon(icons,"▦","C: الملفات",()->open(app()));
        desktopIcon(icons,"◈","D: الهاتف",this::openPhone);
        desktopIcon(icons,"♻","السلة",()->open(trash()));
        desktopIcon(icons,"⚙","الإعدادات",this::settings);
        add(desktop,icons,-1,98);
        stage=new FrameLayout(activity);
        desktop.addView(stage,new LinearLayout.LayoutParams(-1,0,1));
        TextView idle=text("RM11 WINDOWS • مساحة سطح المكتب",21,0xff78c9ff,true);
        idle.setGravity(Gravity.CENTER);
        stage.addView(idle,new FrameLayout.LayoutParams(-1,-1));
        LinearLayout bar=h();bar.setPadding(d(11),d(4),d(11),d(4));
        bar.setBackgroundColor(0xee101728);
        action(bar,"⊞ START",100,this::start);
        action(bar,"▣ الكمبيوتر",114,this::openComputer);
        action(bar,"▤ المستكشف",120,()->open(work()));
        action(bar,"⚙ الإعدادات",106,this::settings);
        action(bar,"— تصغير",84,this::minimize);
        TextView clock=text(DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date()),12,MUTED,true);
        clock.setGravity(Gravity.RIGHT|Gravity.CENTER_VERTICAL);
        bar.addView(clock,new LinearLayout.LayoutParams(0,-1,1));
        action(bar,"← الواجهة الرئيسية",142,closeDesktop);
        add(desktop,bar,-1,53);
        if(Build.VERSION.SDK_INT>=30)root.setOnApplyWindowInsetsListener((w,insets)->{
            Insets b=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout());
            w.setPadding(b.left,b.top,b.right,b.bottom);return insets;
        });
        activity.setContentView(root);
        if(Build.VERSION.SDK_INT>=30)root.requestApplyInsets();
    }
    private void desktopIcon(LinearLayout parent,String icon,String label,Runnable run){
        LinearLayout tile=v();tile.setGravity(Gravity.CENTER);
        tile.setBackground(shape(0xaa1a2940,10));
        TextView glyph=text(icon,27,ACCENT,true);glyph.setGravity(Gravity.CENTER);
        TextView name=text(label,12,WHITE,true);name.setGravity(Gravity.CENTER);
        name.setSingleLine(true);name.setEllipsize(TextUtils.TruncateAt.END);
        add(tile,glyph,-1,43);add(tile,name,-1,29);
        tile.setOnClickListener(w->{dismissStart();run.run();});
        LinearLayout.LayoutParams p=lp(139,84);p.rightMargin=d(9);
        parent.addView(tile,p);
    }
    private void menu(LinearLayout box,String caption,Runnable click){
        LinearLayout.LayoutParams p=lp(-1,40);p.bottomMargin=d(4);
        box.addView(btn(caption,()->{dismissStart();click.run();}),p);
    }
    private void start(){
        if(startPanel!=null){dismissStart();return;}
        startPanel=new FrameLayout(activity);
        LinearLayout options=v();options.setPadding(d(12),d(12),d(12),d(12));
        options.setBackground(shape(0xff17263a,12));
        add(options,text("⊞  START  /  RM11",19,WHITE,true),-1,43);
        menu(options,"▣  هذا الكمبيوتر",this::openComputer);
        menu(options,"▤  مستكشف الملفات",()->open(work()));
        menu(options,"▦  C: ملفات التطبيق",()->open(app()));
        menu(options,"◈  D: الهاتف",this::openPhone);
        menu(options,"♻  سلة المحذوفات",()->open(trash()));
        menu(options,"⚙  الإعدادات",this::settings);
        menu(options,"←  العودة إلى الملفات الرئيسية",closeDesktop);
        startPanel.addView(options,new FrameLayout.LayoutParams(-1,-2));
        FrameLayout.LayoutParams p=new FrameLayout.LayoutParams(d(300),-2,Gravity.BOTTOM|Gravity.LEFT);
        p.leftMargin=d(15);p.bottomMargin=d(57);
        root.addView(startPanel,p);startPanel.setElevation(d(16));
    }
    private void dismissStart(){if(root!=null&&startPanel!=null)root.removeView(startPanel);startPanel=null;}
    void dispose(){dismissStart();back.clear();forward.clear();copied=null;}
    void onPhoneFolderPicked(Uri uri){phoneTree=uri;openPhone();}
    void goBackOrClose(){
        if(startPanel!=null){dismissStart();return;}
        if(window!=null&&!back.isEmpty()){goBack();return;}
        if(window!=null){closeWindow();return;}
        closeDesktop.run();
    }
    private void openPhone(){
        Node n=phone();
        if(n!=null)open(n);
        else new AlertDialog.Builder(activity).setTitle("مجلد الهاتف D:")
            .setMessage("اختار مجلداً للسماح بقراءته من نظام أندرويد. ما راح نغير ملفات الجهاز.")
            .setNegativeButton("إلغاء",null)
            .setPositiveButton("اختيار المجلد",(dlg,which)->pickPhone.run()).show();
    }
    private void openComputer(){open(pc());}
    private void open(Node n){dismissStart();back.clear();forward.clear();current=n;buildWindow();}
    private void closeWindow(){dismissStart();window=null;list=null;search=null;current=null;back.clear();forward.clear();
        if(stage!=null){stage.removeAllViews();TextView idle=text("RM11 WINDOWS • سطح المكتب",19,ACCENT,true);
        idle.setGravity(Gravity.CENTER);stage.addView(idle,new FrameLayout.LayoutParams(-1,-1));}}
    private void minimize(){
        if(window==null){openComputer();return;}
        stage.removeAllViews();window=null;list=null;search=null;
        alert("تم تصغير نافذة المستكشف. اضغط المستكشف أو الكمبيوتر لفتحها.");
    }
    private void buildWindow(){
        if(stage==null)return;stage.removeAllViews();
        window=v();window.setBackground(shape(0xff0f1b2a,12));
        FrameLayout.LayoutParams wp=new FrameLayout.LayoutParams(-1,-1);
        wp.setMargins(d(15),0,d(15),d(12));stage.addView(window,wp);
        window.setElevation(d(9));
        LinearLayout head=h();head.setPadding(d(9),d(2),d(7),d(2));
        head.setBackground(shape(PANEL,10));
        caption=text("▤  File Explorer",16,WHITE,true);
        head.addView(caption,new LinearLayout.LayoutParams(0,-1,1));
        action(head,"—",39,this::minimize);
        action(head,"□",39,()->{
            FrameLayout.LayoutParams cur=(FrameLayout.LayoutParams)window.getLayoutParams();
            int m=cur.leftMargin==0?d(15):0;
            cur.setMargins(m,0,m,cur.leftMargin==0?d(12):0);
            window.setLayoutParams(cur);
        });
        action(head,"✕",39,this::closeWindow);
        add(window,head,-1,45);
        LinearLayout top=h();top.setPadding(d(7),d(3),d(7),d(3));
        action(top,"←",40,this::goBack);
        action(top,"→",40,this::goForward);
        action(top,"↑",40,this::up);
        action(top,"↻",42,this::refresh);
        pathLabel=text("",12,MUTED,false);pathLabel.setSingleLine(true);
        pathLabel.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        pathLabel.setPadding(d(10),0,0,0);pathLabel.setBackground(shape(PANEL,7));
        top.addView(pathLabel,new LinearLayout.LayoutParams(0,d(38),1));
        search=new EditText(activity);search.setSingleLine(true);
        search.setTextColor(WHITE);search.setHintTextColor(MUTED);
        search.setTextSize(12);search.setHint("⌕ بحث");
        search.setPadding(d(9),0,d(9),0);search.setBackground(shape(PANEL,7));
        search.addTextChangedListener(new TextWatcher(){
            public void beforeTextChanged(CharSequence s,int start,int count,int after){}
            public void onTextChanged(CharSequence s,int start,int before,int count){refresh();}
            public void afterTextChanged(Editable e){}
        });
        LinearLayout.LayoutParams searchP=lp(175,38);searchP.leftMargin=d(6);
        top.addView(search,searchP);
        add(window,top,-1,44);
        LinearLayout commands=h();commands.setPadding(d(8),d(1),d(8),d(1));
        action(commands,"+ مجلد",77,()->create(true));
        action(commands,"+ ملف",72,()->create(false));
        action(commands,"▣ لصق",76,this::paste);
        action(commands,"♻ السلة",88,()->navigate(trash()));
        TextView hint=text("C: قراءة   •   W: تعديل   •   D: قراءة الهاتف",11,MUTED,false);
        hint.setGravity(Gravity.RIGHT|Gravity.CENTER_VERTICAL);
        commands.addView(hint,new LinearLayout.LayoutParams(0,-1,1));
        add(window,commands,-1,43);
        LinearLayout area=h();area.setPadding(d(7),d(3),d(7),d(5));
        LinearLayout rail=v();rail.setBackground(shape(PANEL,9));
        rail.setPadding(d(5),d(6),d(5),d(6));
        add(rail,text("QUICK ACCESS",11,ACCENT,true),-1,30);
        rail(rail,"▣  هذا الكمبيوتر",this::openComputer);
        rail(rail,"▦  C: التطبيق",()->navigate(app()));
        rail(rail,"◈  W: مساحة العمل",()->navigate(work()));
        rail(rail,"▤  D: الهاتف",this::openPhone);
        rail(rail,"♻  المحذوفات",()->navigate(trash()));
        area.addView(rail,lp(180,-1));
        LinearLayout right=v();right.setPadding(d(8),0,0,0);
        add(right,text("الاسم                                         النوع / الحجم",11,MUTED,true),-1,27);
        ScrollView scroll=new ScrollView(activity);
        scroll.setBackground(shape(0xff131f30,8));scroll.setFillViewport(true);
        list=v();list.setPadding(d(7),d(6),d(7),d(4));scroll.addView(list);
        right.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        area.addView(right,new LinearLayout.LayoutParams(0,-1,1));
        window.addView(area,new LinearLayout.LayoutParams(-1,0,1));
        status=text("جاهز",11,MUTED,false);status.setPadding(d(12),0,0,0);
        add(window,status,-1,26);
        refresh();
    }
    private void rail(LinearLayout into,String label,Runnable r){
        LinearLayout.LayoutParams p=lp(-1,37);p.bottomMargin=d(5);
        into.addView(btn(label,r),p);
    }
    private void navigate(Node n){
        if(n==null)return;
        if(current!=null)back.push(current);
        if(back.size()>60)back.removeLast();
        forward.clear();current=n;
        if(search!=null)search.setText("");
        refresh();
    }
    private void goBack(){
        if(back.isEmpty()){alert("ماكو مجلد سابق");return;}
        if(current!=null)forward.push(current);
        current=back.pop();if(search!=null)search.setText("");refresh();
    }
    private void goForward(){
        if(forward.isEmpty()){alert("ماكو مجلد لاحق");return;}
        if(current!=null)back.push(current);
        current=forward.pop();if(search!=null)search.setText("");refresh();
    }
    private void up(){
        if(current==null||current.type==PC){openComputer();return;}
        if(current.type==PHONE){
            Node base=phone();
            if(base==null||base.doc.equals(current.doc)){navigate(pc());return;}
            int n=current.doc.lastIndexOf('/');
            navigate(n<0?base:new Node(PHONE,null,current.doc.substring(0,n),"المجلد الأب"));
            return;
        }
        if(current.type==TRASH){navigate(pc());return;}
        File rootDir=current.type==APP?appDir:workspace;
        if(current.file.equals(rootDir)){navigate(pc());return;}
        File parent=current.file.getParentFile();
        if(parent!=null&&in(rootDir,parent))navigate(new Node(current.type,parent,null,parent.getName()));
        else navigate(pc());
    }
    private String address(){
        if(current==null)return "";
        if(current.type==PC)return "This PC / هذا الكمبيوتر";
        if(current.type==PHONE)return "D:\\  "+current.title;
        if(current.type==TRASH)return "W:\\.rm11-recycle";
        File base=current.type==APP?appDir:workspace;
        String prefix=current.type==APP?"C:\\":"W:\\";
        if(current.file.equals(base))return prefix;
        return prefix+base.toPath().relativize(current.file.toPath()).toString().replace('/','\\');
    }
    private String filt(){
        return search==null?"":search.getText().toString().trim().toLowerCase(Locale.ROOT);
    }
    private void refresh(){
        if(list==null||current==null)return;
        list.removeAllViews();
        if(caption!=null)caption.setText("▤  "+current.title+"   —   RM11 Explorer");
        if(pathLabel!=null)pathLabel.setText(address());
        if(current.type==PC)drives();
        else if(current.type==PHONE)phoneRows();
        else localRows();
    }
    private void row(String icon,String name,String info,Runnable click,Runnable longClick){
        LinearLayout item=h();item.setPadding(d(7),d(2),d(7),d(2));
        item.setBackground(shape(ITEM,8));
        TextView glyph=text(icon,23,ACCENT,true);glyph.setGravity(Gravity.CENTER);
        add(item,glyph,43,compact?35:46);
        LinearLayout names=v();
        TextView label=text(name,14,WHITE,true);label.setSingleLine(true);
        label.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        add(names,label,-1,compact?20:25);
        TextView sub=text(info,11,MUTED,false);sub.setSingleLine(true);
        add(names,sub,-1,compact?16:20);
        item.addView(names,new LinearLayout.LayoutParams(0,-2,1));
        add(item,text("›",18,ACCENT,true),22,compact?35:45);
        item.setOnClickListener(w->click.run());
        if(longClick!=null)item.setOnLongClickListener(w->{longClick.run();return true;});
        LinearLayout.LayoutParams p=lp(-1,compact?45:55);p.bottomMargin=d(5);
        list.addView(item,p);
    }
    private void drives(){
        row("▦","C: ملفات التطبيق","App storage • قراءة فقط",()->navigate(app()),null);
        row("◈","W: مساحة العمل","إنشاء ومجلدات وملفات",()->navigate(work()),null);
        row("▤","D: الهاتف","Android document picker • قراءة فقط",this::openPhone,null);
        row("♻","سلة المحذوفات","استعادة ملفات W:",()->navigate(trash()),null);
        status.setText("هذه الأقراص اختصارات للملفات، وليست أقراص Windows حقيقية.");
    }
    private void blank(String message){add(list,text(message,14,MUTED,false),-1,51);}
    private String size(long n){
        if(n<1024)return n+" B";
        if(n<1048576)return n/1024+" KB";
        if(n<1073741824L)return n/1048576+" MB";
        return String.format(Locale.ROOT,"%.1f GB",n/1073741824.0);
    }
    private void localRows(){
        File dir=current.file;
        File rootDir=current.type==APP?appDir:current.type==TRASH?recycle:workspace;
        if(dir==null||!in(rootDir,dir)||!dir.isDirectory()){
            blank("هذا المسار غير متاح");return;
        }
        File[] all=dir.listFiles();
        if(all==null){blank("ما نكدر نقرأ المجلد");return;}
        Arrays.sort(all,Comparator.comparing((File f)->!f.isDirectory())
                .thenComparing(f->f.getName().toLowerCase(Locale.ROOT)));
        int count=0;
        for(File f:all){
            if(count>=180)break;
            if(!in(rootDir,f))continue;
            if(current.type==WORK&&f.equals(recycle))continue;
            if(!f.getName().toLowerCase(Locale.ROOT).contains(filt()))continue;
            boolean folder=f.isDirectory();int kind=current.type;
            row(folder?"▣":"▤",f.getName(),folder?"مجلد":size(Math.max(0,f.length())),
                ()->{if(folder)navigate(new Node(kind,f,null,f.getName()));else properties(f);},
                ()->fileActions(f));
            count++;
        }
        if(count==0)blank("المجلد فارغ أو ماكو نتائج للبحث");
        status.setText(count+" عنصر • "+(current.type==APP?"قراءة فقط":
                current.type==TRASH?"سلة المحذوفات":"اضغط مطولاً لخيارات الملفات")
                +(count==180?" • عرض أول 180 عنصراً":""));
    }
    private void phoneRows(){
        if(phoneTree==null){blank("اختار مجلد الهاتف أولاً");return;}
        int count=0;
        try{
            Uri uri=DocumentsContract.buildChildDocumentsUriUsingTree(phoneTree,current.doc);
            String[] fields={DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE};
            try(Cursor cursor=activity.getContentResolver().query(uri,fields,null,null,null)){
                if(cursor==null){blank("ماكو صلاحية لهذا المجلد");return;}
                int a=cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID);
                int b=cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME);
                int c=cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE);
                int e=cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE);
                while(cursor.moveToNext()&&count<180){
                    String id=cursor.getString(a),name=cursor.getString(b);
                    if(name==null||!name.toLowerCase(Locale.ROOT).contains(filt()))continue;
                    boolean folder=DocumentsContract.Document.MIME_TYPE_DIR.equals(cursor.getString(c));
                    long bytes=e<0||cursor.isNull(e)?0:cursor.getLong(e);
                    row(folder?"▣":"▤",name,folder?"مجلد":size(bytes),
                        ()->{if(folder)navigate(new Node(PHONE,null,id,name));
                            else new AlertDialog.Builder(activity).setTitle(name)
                                    .setMessage("الحجم: "+size(bytes)+"\nالملف موجود في هاتفك ولم يُغيَّر.")
                                    .setPositiveButton("إغلاق",null).show();},null);
                    count++;
                }
            }
        }catch(Exception ex){blank("تعذرت قراءة مجلد الهاتف، اختاره مرة ثانية");return;}
        if(count==0)blank("ماكو نتائج");
        status.setText(count+" عنصر • الهاتف للقراءة فقط.");
    }
    private void properties(File f){
        new AlertDialog.Builder(activity).setTitle(f.getName())
          .setMessage("المسار: "+f.getAbsolutePath()+"\nالحجم: "+size(Math.max(0,f.length()))
             +"\nآخر تعديل: "+DateFormat.getDateTimeInstance().format(new Date(f.lastModified()))
             +"\n\nلا يتم تشغيل ملفات EXE في هذه الواجهة.")
          .setPositiveButton("إغلاق",null).show();
    }
    private boolean nameOk(String s){
        return s!=null&&!s.trim().isEmpty()&&s.length()<181&&!s.equals(".")&&!s.equals("..")
                &&!s.contains("/")&&!s.contains("\\")&&s.indexOf('\0')<0;
    }
    private void ask(String title,String initial,java.util.function.Consumer<String> action){
        EditText input=new EditText(activity);input.setSingleLine(true);input.setText(initial);
        new AlertDialog.Builder(activity).setTitle(title).setView(input)
            .setNegativeButton("إلغاء",null)
            .setPositiveButton("حفظ",(dialog,which)->{
                String s=input.getText().toString().trim();
                if(!nameOk(s)){alert("اسم غير صالح");return;}action.accept(s);
            }).show();
    }
    private void create(boolean folder){
        if(!writable()){alert("الإنشاء داخل W: مساحة العمل فقط");return;}
        File parent=current.file;
        ask(folder?"مجلد جديد":"ملف جديد",folder?"مجلد جديد":"ملاحظة.txt",name->{
            File f=new File(parent,name);
            try{
                if(!in(workspace,f)||f.exists())throw new IOException();
                if(!(folder?f.mkdir():f.createNewFile()))throw new IOException();
                refresh();
            }catch(IOException e){alert("الاسم موجود أو تعذر إنشاء الملف");}
        });
    }
    private void fileActions(File f){
        if(current.type==TRASH){
            new AlertDialog.Builder(activity).setTitle(f.getName())
              .setItems(new String[]{"استعادة الملف","خصائص"},(dialog,n)->{
                  if(n==0)restore(f);else properties(f);
              }).show();return;
        }
        if(current.type!=WORK||!in(workspace,f)||in(recycle,f)){properties(f);return;}
        String[] options=f.isFile()?new String[]{"تعديل نص","نسخ","إعادة تسمية","نقل للسلة","خصائص"}
                :new String[]{"فتح المجلد","إعادة تسمية","نقل للسلة","خصائص"};
        new AlertDialog.Builder(activity).setTitle(f.getName()).setItems(options,(dlg,n)->{
            String op=options[n];
            if(op.equals("تعديل نص"))edit(f);
            else if(op.equals("نسخ")){copied=f;alert("انسخ ثم افتح المجلد المطلوب واضغط لصق");}
            else if(op.equals("إعادة تسمية"))rename(f);
            else if(op.equals("نقل للسلة"))moveTrash(f);
            else if(op.equals("فتح المجلد"))navigate(new Node(WORK,f,null,f.getName()));
            else properties(f);
        }).show();
    }
    private void rename(File f){
        ask("إعادة تسمية",f.getName(),name->{
            File dest=new File(f.getParentFile(),name);
            if(!in(workspace,dest)||in(recycle,dest)||dest.exists()||!f.renameTo(dest))
                alert("تعذرت إعادة التسمية");
            else refresh();
        });
    }
    private void paste(){
        if(!writable()||copied==null||!copied.isFile()||!in(workspace,copied)
                ||in(recycle,copied)){alert("انسخ ملفاً من W: للصق داخل مساحة العمل");return;}
        if(copied.length()>128*1024*1024L){alert("النسخ محدود حتى 128 MB");return;}
        File dest=new File(current.file,copied.getName());
        if(!in(workspace,dest)||dest.exists()){alert("الاسم موجود أو المسار غير صالح");return;}
        try{Files.copy(copied.toPath(),dest.toPath());refresh();}
        catch(IOException e){alert("تعذر نسخ الملف");}
    }
    private void moveTrash(File f){
        if(!in(workspace,f)||in(recycle,f))return;
        new AlertDialog.Builder(activity).setTitle("النقل إلى سلة المحذوفات")
         .setMessage("يمكن استعادة هذا الملف لاحقاً، ولا يوجد حذف نهائي.")
         .setNegativeButton("إلغاء",null)
         .setPositiveButton("نقل",(dlg,which)->{
             String key=System.currentTimeMillis()+"_"+Math.abs(f.getName().hashCode());
             File dest=new File(recycle,key);
             if(!in(recycle,dest)||!f.renameTo(dest)){alert("تعذّر النقل");return;}
             pref.edit().putString("trash/"+key,f.getAbsolutePath()).apply();refresh();
         }).show();
    }
    private void restore(File f){
        if(!in(recycle,f))return;
        String path=pref.getString("trash/"+f.getName(),null);
        if(path==null){alert("مسار الاستعادة غير موجود");return;}
        File target=new File(path);
        if(!in(workspace,target)||in(recycle,target)||target.exists()
                ||!target.getParentFile().isDirectory()||!f.renameTo(target)){
            alert("تعذر الاسترجاع. تأكد من وجود المجلد الأصلي.");return;
        }
        pref.edit().remove("trash/"+f.getName()).apply();refresh();
    }
    private void edit(File f){
        String name=f.getName().toLowerCase(Locale.ROOT);
        if(!f.isFile()||!in(workspace,f)||in(recycle,f)
                ||!(name.endsWith(".txt")||name.endsWith(".md")||name.endsWith(".log"))
                ||f.length()>65536){properties(f);return;}
        try{
            EditText field=new EditText(activity);
            field.setMinLines(6);field.setMaxLines(15);
            field.setText(new String(Files.readAllBytes(f.toPath()),StandardCharsets.UTF_8));
            ScrollView sc=new ScrollView(activity);sc.addView(field);
            new AlertDialog.Builder(activity).setTitle("تحرير "+f.getName()).setView(sc)
                .setNegativeButton("إلغاء",null)
                .setPositiveButton("حفظ",(dlg,n)->{
                    byte[] bytes=field.getText().toString().getBytes(StandardCharsets.UTF_8);
                    if(bytes.length>65536){alert("الملف كبير");return;}
                    try{Files.write(f.toPath(),bytes);refresh();}
                    catch(IOException ex){alert("تعذر الحفظ");}
                }).show();
        }catch(IOException e){alert("تعذر فتح الملف");}
    }
    private void settings(){
        dismissStart();
        new AlertDialog.Builder(activity).setTitle("⚙ إعدادات RM11 Windows")
          .setMessage("واجهة Windows مصممة داخل Android، وليست نظام Microsoft Windows.\n\n"
              +"C: ملفات التطبيق — للقراءة\nW: مساحة العمل — تعديل ونسخ وسلة\n"
              +"D: ملفات الهاتف — قراءة بموافقتك\n\n"
              +"لا يتم تشغيل EXE أو Wine أو X11 في هذا الإصدار.\n"
              +"بيانات التطبيق القديمة محفوظة.")
          .setNegativeButton("إغلاق",null)
          .setNeutralButton(compact?"أيقونات أكبر":"أيقونات أصغر",(dlg,n)->{
              compact=!compact;pref.edit().putBoolean("compact",compact).apply();
              if(window!=null)buildWindow();
          })
          .setPositiveButton("اختيار مجلد الهاتف",(dlg,n)->pickPhone.run()).show();
    }
}
