package com.rm11.autocore;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.provider.DocumentsContract;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.graphics.Insets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.rm11.autocore.diagnostics.OfflineDiagnosticArchive;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Reliable, Android-native front end for RM11. Wine's X11 display remains
 * available separately; an unmapped Wine window must never hide drive files.
 * This screen does NOT pretend to render Wine's GUI, nor does it launch games.
 */
public final class RM11FileLauncherActivity extends Activity {
    private static final int PICK_TREE = 9461;
    private static final int SAVE_DIAGNOSTICS = 9462;
    private static final int BG = 0xff0c1424;
    private static final int PANEL = 0xff17243a;
    private static final int SUBTLE = 0xff243550;
    private static final int TEXT = 0xfff1f5fb;
    private static final int MUTED = 0xff9aaec8;
    private static final int ACCENT = 0xff3972c9;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ArrayDeque<Folder> stack = new ArrayDeque<>();
    private TextView heading, breadcrumb, status;
    private LinearLayout listing;
    private RuntimeLayout layout;
    private Uri pickedTree;
    private boolean launchWindowsAfterStorageGrant;
    private static final class Folder {
        final File local;
        final String documentId;
        final String display;
        Folder(File file, String display) { local=file; documentId=null; this.display=display; }
        Folder(String id, String display) { local=null; documentId=id; this.display=display; }
    }

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        // REDMAGIC / recent Android enforces edge-to-edge in landscape.
        // Explicitly reserve system bar insets for our native dashboard.
        getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN);
        if (Build.VERSION.SDK_INT >= 30)
            getWindow().setDecorFitsSystemWindows(false);
        layout = new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
        createInterface();
        String previous = getPreferences(0).getString("rm11_selected_tree", null);
        if(previous != null) {
            try { pickedTree = Uri.parse(previous); }
            catch(RuntimeException ignored) { pickedTree=null; }
        }
        openCDrive();
    }

    private int dp(int px) {
        return Math.round(getResources().getDisplayMetrics().density * px);
    }
    private GradientDrawable panel(int background,int radius) {
        GradientDrawable g=new GradientDrawable();
        g.setColor(background);
        g.setCornerRadius(dp(radius));
        return g;
    }
    private TextView text(String label,int sp,int color,boolean bold) {
        TextView t=new TextView(this);
        t.setText(label);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setGravity(Gravity.CENTER_VERTICAL);
        t.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
        if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        return t;
    }
    private LinearLayout vertical() {
        LinearLayout l=new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }
    private LinearLayout horizontal() {
        LinearLayout l=new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        l.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        return l;
    }
    private Button action(String title,Runnable click) {
        Button b=new Button(this);
        b.setText(title);
        b.setTextSize(15);
        b.setAllCaps(false);
        b.setTextColor(TEXT);
        b.setBackground(panel(SUBTLE,10));
        b.setOnClickListener(v->click.run());
        return b;
    }
    private LinearLayout.LayoutParams lp(int width,int height,int bottom) {
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(
                width<0?width:dp(width),height<0?height:dp(height));
        p.bottomMargin=dp(bottom);
        return p;
    }
    private void createInterface() {
        LinearLayout entire=vertical();
        entire.setBackgroundColor(BG);
        entire.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        entire.setPadding(dp(14),dp(12),dp(14),dp(12));
        // Unlike the inherited Lorie fullscreen surface, native files need
        // safe top/bottom/side insets so toolbar never overlaps 144 Hz status.
        if (Build.VERSION.SDK_INT >= 30) {
            entire.setOnApplyWindowInsetsListener((view, insets) -> {
                Insets bars=insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout());
                view.setPadding(dp(14)+bars.left,dp(12)+bars.top,
                        dp(14)+bars.right,dp(12)+bars.bottom);
                return insets;
            });
        }
        LinearLayout titleRow=horizontal();
        TextView brand=text("RM11  /  FILES",24,TEXT,true);
        titleRow.addView(brand,new LinearLayout.LayoutParams(0,dp(48),1));
        Button desktop=action("فتح سطح مكتب Windows",this::launchWindowsWithPhoneDrive);
        titleRow.addView(desktop,lp(230,48,0));
        entire.addView(titleRow,lp(-1,52,10));
        LinearLayout area=horizontal();
        area.setGravity(Gravity.TOP);
        area.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        LinearLayout menu=vertical();
        menu.setBackground(panel(PANEL,12));
        menu.setPadding(dp(12),dp(14),dp(12),dp(10));
        menu.addView(text("المواقع والأقراص",18,TEXT,true),lp(-1,38,10));
        menu.addView(action("C:  Windows",this::openCDrive),lp(-1,50,8));
        menu.addView(action("D:  ملفات الهاتف في Windows",this::enablePhoneDrive),lp(-1,54,8));
        menu.addView(action("ملفات RM11",()->openLocal(getFilesDir(),"ملفات RM11")),lp(-1,50,8));
        menu.addView(action("مجلدات الهاتف",this::pickPhoneFolder),lp(-1,50,8));
        menu.addView(action("آخر مجلد هاتف",this::openLastPhoneFolder),lp(-1,50,8));
        menu.addView(text("تصفح الملفات محلياً عبر أندرويد. سطح مكتب Wine مستقل عن هذه القائمة.",13,MUTED,false),lp(-1,-2,14));
        menu.addView(action("التشخيصات",()->startActivity(new Intent(this,MainActivity.class))),lp(-1,48,8));
        menu.addView(action("حفظ تقرير ZIP",this::startZipExport),lp(-1,48,0));
        // Sidebar actions must stay reachable on landscape phones with short
        // available height (system bars + orientation cutout).
        ScrollView sideScroll=new ScrollView(this);
        sideScroll.setFillViewport(true);
        sideScroll.setVerticalScrollBarEnabled(true);
        sideScroll.setBackground(panel(PANEL,12));
        sideScroll.addView(menu,new ScrollView.LayoutParams(-1,-2));
        area.addView(sideScroll,lp(225,-1,0));
        LinearLayout main=vertical();
        main.setPadding(dp(14),0,0,0);
        heading=text("مدير الملفات",23,TEXT,true);
        main.addView(heading,lp(-1,38,2));
        LinearLayout nav=horizontal();
        breadcrumb=text("",13,MUTED,false);
        nav.addView(breadcrumb,new LinearLayout.LayoutParams(0,dp(38),1));
        nav.addView(action("رجوع",this::goBack),lp(90,38,0));
        main.addView(nav,lp(-1,44,8));
        ScrollView scroller=new ScrollView(this);
        scroller.setFillViewport(true);
        scroller.setBackground(panel(PANEL,12));
        listing=vertical();
        listing.setPadding(dp(12),dp(10),dp(12),dp(10));
        scroller.addView(listing);
        main.addView(scroller,new LinearLayout.LayoutParams(-1,0,1));
        status=text("واجهة الملفات تعمل مستقلة عن Wine وX11.",13,MUTED,false);
        main.addView(status,lp(-1,42,0));
        area.addView(main,new LinearLayout.LayoutParams(0,-1,1));
        entire.addView(area,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(entire);
        if (Build.VERSION.SDK_INT >= 30) entire.requestApplyInsets();
    }

    private boolean privateFile(File f) {
        try {
            String home=getFilesDir().getCanonicalPath();
            String path=f.getCanonicalPath();
            return path.equals(home)||path.startsWith(home+File.separator);
        }catch(IOException ex){return false;}
    }
    private void launchWindowsWithPhoneDrive() {
        if(PhoneDriveBridge.authorized()) {
            mountAndEnterWindows();
            return;
        }
        // Explain why Android phone files are absent from Wine. The
        // user explicitly chooses to grant all-files access or decline.
        new AlertDialog.Builder(this)
                .setTitle("ملفات الهاتف داخل Windows")
                .setMessage("حتى تظهر التنزيلات وباقي ملفات الهاتف داخل قرص D: في Windows، يحتاج RM11 إذن الوصول إلى جميع الملفات من أندرويد. ما ننقل ملفاتك ولا نغيّر قرص C:. تگدر تدخل بدون الإذن أيضاً.")
                .setPositiveButton("تفعيل قرص D:",(d,w)->{
                    launchWindowsAfterStorageGrant=true;
                    try {
                        Intent permission=PhoneDriveBridge.permissionIntent(this);
                        if(permission!=null)startActivity(permission);
                    }catch(RuntimeException ex) {
                        launchWindowsAfterStorageGrant=false;
                        status.setText("تعذر فتح صلاحية ملفات الهاتف: "+
                                ex.getClass().getSimpleName());
                    }
                })
                .setNegativeButton("فتح Windows بدون D:",(d,w)->
                        startActivity(new Intent(this,RM11NativeWineActivity.class)))
                .show();
    }

    private void mountAndEnterWindows() {
        worker.execute(()->{
            String result=PhoneDriveBridge.mountIfAuthorized(this,layout);
            String diagnosis=PhoneDriveBridge.status(this,layout);
            OfflineDiagnosticJournal.record(this,"v415-user-phone-drive",
                    result+"\n"+diagnosis);
            ui.post(()->{
                if(isFinishing())return;
                status.setText("قرص الهاتف: "+result);
                startActivity(new Intent(this,RM11NativeWineActivity.class));
            });
        });
    }

    private void enablePhoneDrive() {
        if(!PhoneDriveBridge.authorized()) {
            new AlertDialog.Builder(this)
                    .setTitle("قرص الهاتف داخل Windows")
                    .setMessage("حتى تظهر ملفات الجهاز كاملة داخل مدير Windows على القرص D:، يحتاج التطبيق صلاحية «الوصول إلى جميع الملفات» من إعدادات أندرويد. هذه الصلاحية اختيارية، وبدونها يبقى تصفح مجلد تختاره عبر أندرويد متاحاً. لا تُحذف أو تُنسخ ملفاتك.")
                    .setPositiveButton("فتح صلاحية ملفات الهاتف",(d,w)->{
                        try {
                            Intent intent=PhoneDriveBridge.permissionIntent(this);
                            if(intent!=null)startActivity(intent);
                        } catch(RuntimeException ex) {
                            try {
                                startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                            } catch(RuntimeException ignored) {
                                status.setText("تعذر فتح إعدادات الوصول للملفات في هذا الجهاز.");
                            }
                        }
                    })
                    .setNegativeButton("لاحقاً",null).show();
            return;
        }
        String outcome=PhoneDriveBridge.mountIfAuthorized(this,layout);
        OfflineDiagnosticJournal.record(this,"v414-phone-drive-mount",outcome);
        status.setText(outcome);
        new AlertDialog.Builder(this)
                .setTitle(outcome.contains("MOUNTED")?"قرص D: جاهز":"حالة قرص الهاتف")
                .setMessage(outcome.contains("MOUNTED")
                        ?"صار تگدر تفتح ملفات الهاتف من مدير Windows بواسطة القرص D: بعد فتح سطح المكتب من الزر العلوي."
                        :"ما تمكنت من ربط القرص. ما غيّرنا أي قرص سابق داخل Wine.\n"+outcome)
                .setPositiveButton("تم",null).show();
    }

    @Override protected void onResume() {
        super.onResume();
        if(layout!=null && launchWindowsAfterStorageGrant) {
            launchWindowsAfterStorageGrant=false;
            if(PhoneDriveBridge.authorized()) {
                mountAndEnterWindows();
                return;
            }
            status.setText("لم تُمنح صلاحية الملفات. يمكن فتح Windows بدون قرص D:");
        }
        if(layout!=null && PhoneDriveBridge.authorized()) {
            worker.execute(()->{
                String state=PhoneDriveBridge.mountIfAuthorized(this,layout);
                OfflineDiagnosticJournal.record(this,"v414-phone-drive-authorization",state);
                ui.post(()->{
                    if(!isFinishing() && status!=null && state.contains("MOUNTED"))
                        status.setText("الهاتف جاهز بقرص D: في مدير ملفات Windows.");
                });
            });
        }
    }

    private void openCDrive() {
        File drive=layout.winePrefix.resolve("drive_c").toFile();
        if(drive.isDirectory()&&privateFile(drive)) openLocal(drive,"C:");
        else {
            openLocal(getFilesDir(),"ملفات RM11");
            status.setText("قرص C: غير مهيأ بعد؛ افتح Windows حتى تُجهّز ملفات Wine.");
        }
    }
    private void openLocal(File dir,String label) {
        stack.clear();
        stack.push(new Folder(dir,label));
        updateFiles();
    }
    private void enterLocal(File dir,String label) {
        stack.push(new Folder(dir,label));
        updateFiles();
    }
    private void goBack() {
        if(stack.size()>1) {
            stack.pop();
            updateFiles();
        } else if(!stack.isEmpty()) {
            status.setText("أنت في بداية هذا الموقع. اختر قرصاً أو مجلداً من القائمة.");
        }
    }
    @Override public void onBackPressed() {
        if(stack.size()>1)goBack();
        else super.onBackPressed();
    }
    private String size(long count) {
        if(count<1024)return count+" B";
        if(count<1024*1024)return (count/1024)+" KB";
        if(count<1024L*1024L*1024L)return (count/(1024*1024))+" MB";
        return String.format(java.util.Locale.ROOT,"%.1f GB",count/(1024.0*1024*1024));
    }
    private void drawEntry(String name,boolean dir,long bytes,Runnable open) {
        LinearLayout item=horizontal();
        item.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        item.setPadding(dp(14),dp(5),dp(12),dp(5));
        item.setBackground(panel(0xff1e304b,9));
        TextView symbol=text(dir?"📁":"📄",20,TEXT,false);
        item.addView(symbol,lp(46,48,0));
        LinearLayout labels=vertical();
        TextView title=text(name,17,TEXT,true);
        title.setSingleLine(true);
        title.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        labels.addView(title,lp(-1,29,0));
        labels.addView(text(dir?"مجلد":size(Math.max(0,bytes)),12,MUTED,false),lp(-1,20,0));
        item.addView(labels,new LinearLayout.LayoutParams(0,dp(52),1));
        item.addView(text("›",23,MUTED,false),lp(24,50,0));
        item.setOnClickListener(v->open.run());
        listing.addView(item,lp(-1,63,7));
    }
    private void updateFiles() {
        listing.removeAllViews();
        Folder current=stack.peek();
        if(current==null)return;
        heading.setText("ملفاتي  /  "+current.display);
        StringBuilder crumb=new StringBuilder();
        for(java.util.Iterator<Folder> i=stack.descendingIterator();i.hasNext();) {
            if(crumb.length()>0)crumb.append("  /  ");
            crumb.append(i.next().display);
        }
        breadcrumb.setText(crumb.toString());
        if(current.local!=null) {
            if(!privateFile(current.local)||!current.local.isDirectory()) {
                status.setText("هذا المجلد غير متاح أو خارج مساحة التطبيق الآمنة.");
                return;
            }
            File[] contents=current.local.listFiles();
            if(contents==null) {
                status.setText("أندرويد رفض قراءة هذا المجلد.");
                return;
            }
            Arrays.sort(contents,Comparator.comparing((File f)->!f.isDirectory())
                    .thenComparing(f->f.getName().toLowerCase(java.util.Locale.ROOT)));
            int count=0,blocked=0;
            for(File file:contents) {
                if(count>=250)break;
                if(!privateFile(file)){blocked++;continue;}
                String name=file.getName();
                if(file.isDirectory())drawEntry(name,true,0,()->enterLocal(file,name));
                else if(file.isFile())drawEntry(name,false,file.length(),
                        ()->showLocalFile(file));
                count++;
            }
            if(count==0)listing.addView(text("هذا المجلد فارغ.",17,MUTED,false),lp(-1,54,0));
            status.setText("عُرض "+count+" عنصر؛ العناصر غير المسموح بها: "+blocked
                    +(contents.length>250?" — العرض محدود بأول 250 عنصر":""));
        } else showPhoneChildren(current);
    }
    private void showLocalFile(File file) {
        new AlertDialog.Builder(this).setTitle(file.getName())
                .setMessage("الحجم: "+size(file.length())+
                        "\nالمسار: "+file.getAbsolutePath()+
                        "\n\nتصفح الملفات متاح. تشغيل البرامج متعددة الملفات من هذه القائمة يحتاج ربط القرص بمحرك Wine، ولا ندّعي أنه جاهز.")
                .setPositiveButton("تم",null).show();
    }
    private void pickPhoneFolder() {
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try {startActivityForResult(intent,PICK_TREE);}
        catch(RuntimeException e){status.setText("منتقي مجلدات الهاتف غير متاح.");}
    }
    private void openLastPhoneFolder() {
        if(pickedTree==null){pickPhoneFolder();return;}
        try {
            String root=DocumentsContract.getTreeDocumentId(pickedTree);
            stack.clear();
            stack.push(new Folder(root,"مجلد الهاتف"));
            updateFiles();
        }catch(Exception e){status.setText("صلاحية المجلد انتهت؛ اختر المجلد مرة أخرى.");}
    }
    private void showPhoneChildren(Folder current) {
        if(pickedTree==null){status.setText("لم يُحدد مجلد هاتف.");return;}
        Uri children=DocumentsContract.buildChildDocumentsUriUsingTree(
                pickedTree,current.documentId);
        String[] cols={DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE};
        ArrayList<PhoneEntry> entries=new ArrayList<>();
        try(Cursor c=getContentResolver().query(children,cols,null,null,null)) {
            if(c==null)throw new IOException("Document provider returned null");
            while(c.moveToNext()&&entries.size()<350) {
                String id=c.getString(0),name=c.getString(1),mime=c.getString(2);
                long length=c.isNull(3)?0:c.getLong(3);
                if(id!=null)entries.add(new PhoneEntry(id,name==null?"(بدون اسم)":name,
                        DocumentsContract.Document.MIME_TYPE_DIR.equals(mime),length));
            }
            entries.sort(Comparator.comparing((PhoneEntry e)->!e.folder)
                    .thenComparing(e->e.name.toLowerCase(java.util.Locale.ROOT)));
            int shown=0;
            for(PhoneEntry e:entries) {
                if(shown++>=250)break;
                drawEntry(e.name,e.folder,e.length,()->{
                    if(e.folder) {
                        stack.push(new Folder(e.id,e.name));
                        updateFiles();
                    } else showPhoneFile(e);
                });
            }
            if(entries.isEmpty())listing.addView(text("هذا المجلد فارغ.",17,MUTED,false),lp(-1,54,0));
            status.setText("تم عرض "+Math.min(250,entries.size())+" عنصراً من مجلد الهاتف (قراءة فقط).");
        }catch(Exception ex){
            status.setText("تعذر قراءة مجلد الهاتف: "+ex.getClass().getSimpleName()
                    +" — اختره مجدداً من القائمة.");
        }
    }
    private static final class PhoneEntry {
        final String id,name;
        final boolean folder;
        final long length;
        PhoneEntry(String id,String name,boolean folder,long length) {
            this.id=id;this.name=name;this.folder=folder;this.length=length;
        }
    }
    private void showPhoneFile(PhoneEntry entry) {
        Uri doc=DocumentsContract.buildDocumentUriUsingTree(pickedTree,entry.id);
        boolean tinyExe=entry.name.toLowerCase(java.util.Locale.ROOT).endsWith(".exe")
                && entry.length>0&&entry.length<=16L*1024*1024;
        AlertDialog.Builder popup=new AlertDialog.Builder(this)
                .setTitle(entry.name)
                .setMessage("الحجم: "+size(entry.length)+
                        "\n\nملف الهاتف محفوظ بمكانه. لا يتم نسخ ملفات الألعاب أو تعديلها."
                        +(tinyExe?"\nيتوفر اختبار Wine لملف PE64 واحد حتى 16 MB فقط.":
                        "\nتشغيل الألعاب الكبيرة وملفاتها التابعة غير موصول بهذه الواجهة بعد."))
                .setNegativeButton("رجوع",null);
        if(tinyExe)popup.setPositiveButton("اختبار EXE صغير",(d,w)->pilotExe(doc));
        popup.show();
    }
    private void pilotExe(Uri source) {
        status.setText("اختبار EXE صغير في Wine، دون تشغيل واجهة لعبة.");
        worker.execute(()->{
            String report=ExternalExeRunnerV270.run(this,source);
            ui.post(()->{
                status.setText("اكتمل الاختبار؛ راجع التقرير.");
                new AlertDialog.Builder(this).setTitle("نتيجة EXE")
                        .setMessage(report.substring(0,Math.min(9000,report.length())))
                        .setPositiveButton("حسناً",null).show();
            });
        });
    }
    private void startZipExport() {
        Intent out=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        out.addCategory(Intent.CATEGORY_OPENABLE);
        out.setType("application/zip");
        out.putExtra(Intent.EXTRA_TITLE,"RM11-Native-Desktop-Diagnostics.zip");
        startActivityForResult(out,SAVE_DIAGNOSTICS);
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null)return;
        if(request==PICK_TREE) {
            pickedTree=data.getData();
            try { getContentResolver().takePersistableUriPermission(
                    pickedTree,Intent.FLAG_GRANT_READ_URI_PERMISSION); }
            catch(SecurityException ignored) { }
            getPreferences(0).edit().putString("rm11_selected_tree",pickedTree.toString()).apply();
            openLastPhoneFolder();
        } else if(request==SAVE_DIAGNOSTICS) {
            Uri to=data.getData();
            status.setText("جاري تصدير السجلات...");
            worker.execute(()->{
                try(OutputStream output=getContentResolver().openOutputStream(to)) {
                    if(output==null)throw new IOException("Document provider declined output");
                    OfflineDiagnosticArchive.export(this,output);
                    ui.post(()->status.setText("تم حفظ تقرير ZIP بنجاح."));
                }catch(Exception error){
                    ui.post(()->status.setText("فشل حفظ ZIP: "+error.getClass().getSimpleName()));
                }
            });
        }
    }
    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
