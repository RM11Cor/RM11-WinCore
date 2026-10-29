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
import android.os.Environment;
import android.provider.DocumentsContract;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import com.rm11.autocore.runtime.GameDocumentPathPolicy;
import com.rm11.autocore.runtime.NovaWineExeLauncher;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.RuntimeLayout;
import java.io.File;
import java.util.List;
import java.util.Locale;

/** First-screen game tiles, existing file manager and offline diagnostics kept. */
public final class RM11GameLibraryActivity extends Activity {
    private static final int PICK_GAME=49038, BG=0xff0a0f17;
    private static final int CARD=0xff1a2634, HILITE=0xfff04452;
    private LinearLayout tiles;
    private TextView count,info;
    private boolean gameOpening=false;
    private int dp(int px){return Math.round(getResources().getDisplayMetrics().density*px);}
    private GradientDrawable bg(int color,int radius){
        GradientDrawable d=new GradientDrawable();
        d.setColor(color);d.setCornerRadius(dp(radius));
        d.setStroke(dp(1),0xff364557);return d;
    }
    private TextView text(String title,int size,int color,boolean bold) {
        TextView t=new TextView(this);
        t.setText(title);t.setTextColor(color);t.setTextSize(size);
        t.setGravity(Gravity.CENTER_VERTICAL);
        if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        t.setSingleLine(false);return t;
    }
    private Button button(String caption,View.OnClickListener listener){
        Button b=new Button(this);
        b.setText(caption);b.setAllCaps(false);
        b.setTextColor(Color.WHITE);b.setTextSize(13);
        b.setBackground(bg(CARD,12));b.setOnClickListener(listener);
        return b;
    }
    private LinearLayout vertical(){
        LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);return v;
    }
    private LinearLayout row(){
        LinearLayout r=new LinearLayout(this);r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);return r;
    }
    private LinearLayout.LayoutParams spacing(int w,int h,int l,int t,int r,int b){
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(
            w<0?w:dp(w),h<0?h:dp(h));
        p.setMargins(dp(l),dp(t),dp(r),dp(b));return p;
    }
    @Override protected void onCreate(Bundle saved){
        super.onCreate(saved);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        createUi();
    }
    private void createUi(){
        LinearLayout root=vertical();root.setBackgroundColor(BG);
        root.setPadding(dp(20),dp(12),dp(20),dp(10));
        LinearLayout toolbar=row();
        TextView brand=text("RM11  /  GAME LIBRARY",23,Color.WHITE,true);
        toolbar.addView(brand,new LinearLayout.LayoutParams(0,dp(52),1));
        toolbar.addView(button("+ إضافة لعبة EXE",v->pickGame()),spacing(155,49,8,0,0,0));
        toolbar.addView(button("▣ مدير الملفات",v->startActivity(
                new Intent(this,RM11FilesOnlyActivity.class))),spacing(145,49,8,0,0,0));
        root.addView(toolbar,spacing(-1,58,0,0,0,10));

        LinearLayout banner=vertical();banner.setBackground(bg(CARD,13));
        banner.setPadding(dp(16),dp(12),dp(15),dp(13));
        banner.addView(text("ألعابك في مكان واحد",21,0xfff4f7fa,true));
        banner.addView(text("أضف ملف EXE من ذاكرة الهاتف أو من مدير الملفات. "
                +"تشغيل مباشر من مجلد اللعبة الأصلي — بدون نسخ ملفات اللعبة.",13,0xffacbed2,false));
        root.addView(banner,spacing(-1,-2,0,0,0,10));
        LinearLayout heading=row();
        count=text("الألعاب",18,Color.WHITE,true);
        heading.addView(count,new LinearLayout.LayoutParams(0,dp(40),1));
        heading.addView(button("↻ تحديث",v->refresh()),spacing(106,40,6,0,0,0));
        root.addView(heading,spacing(-1,44,0,0,0,5));
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);
        tiles=vertical();tiles.setPadding(dp(2),dp(4),dp(2),dp(9));
        scroll.addView(tiles);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        info=text("جاهز — المحاكي يحافظ على ملفاتك الأصلية.",12,0xffb6c9db,false);
        root.addView(info,spacing(-1,28,0,4,0,0));
        setContentView(root);refresh();
    }
    private void refresh(){
        if(tiles==null)return;
        tiles.removeAllViews();
        List<RM11GameLibraryStore.Game> games=RM11GameLibraryStore.list(this);
        count.setText("مكتبة الألعاب  •  "+games.size());
        if(games.isEmpty()){
            LinearLayout empty=vertical();empty.setPadding(dp(24),dp(27),dp(24),dp(26));
            empty.setBackground(bg(CARD,14));
            TextView emoji=text("🎮  ما أضفت ألعاب بعد",21,Color.WHITE,true);
            emoji.setGravity(Gravity.CENTER);empty.addView(emoji);
            TextView hint=text("اضغط «إضافة لعبة EXE» أو افتح مدير الملفات وحدد لعبة ثم «أضف للمكتبة».",14,
                0xffb7cbdd,false);hint.setGravity(Gravity.CENTER);
            empty.addView(hint,spacing(-1,-2,0,15,0,10));
            tiles.addView(empty,spacing(-1,-2,0,10,0,0));return;
        }
        GridLayout grid=new GridLayout(this);grid.setColumnCount(3);
        grid.setUseDefaultMargins(false);
        for(RM11GameLibraryStore.Game g:games){
            File exe=new File(g.path);
            boolean exists=exe.isFile();
            LinearLayout tile=vertical();tile.setBackground(bg(CARD,13));
            tile.setPadding(dp(15),dp(14),dp(15),dp(12));
            TextView icon=text("🎮",29,Color.WHITE,true);
            icon.setGravity(Gravity.CENTER);
            tile.addView(icon,spacing(-1,50,0,0,0,0));
            TextView title=text(g.title,17,Color.WHITE,true);
            title.setMaxLines(2);title.setGravity(Gravity.CENTER);
            tile.addView(title,spacing(-1,45,0,0,0,4));
            TextView state=text(exists?"جاهزة للتشغيل":"الملف غير موجود",12,
                   exists?0xff68d9ab:0xffffaa77,false);
            state.setGravity(Gravity.CENTER);
            tile.addView(state,spacing(-1,28,0,0,0,7));
            Button play=button(exists?"▶ تشغيل":"تحديد الملف من جديد",v->{
                if(exists)launchGame(exe);
                else info.setText("مسار اللعبة غير موجود. احذف البطاقة ثم أضف ملف EXE من مكانه الجديد.");
            });
            tile.addView(play,spacing(-1,42,0,0,0,5));
            Button remove=button("إزالة من المكتبة",v->{
                new AlertDialog.Builder(this).setTitle("إزالة البطاقة؟")
                   .setMessage("راح نحذف اللعبة من القائمة فقط، بدون المساس بملف EXE أو بياناتها.")
                   .setNegativeButton("إلغاء",null)
                   .setPositiveButton("إزالة",(dialog,w)->{
                        RM11GameLibraryStore.remove(this,g.path);refresh();
                   }).show();
            });
            tile.addView(remove,spacing(-1,36,0,0,0,0));
            GridLayout.LayoutParams gp=new GridLayout.LayoutParams();
            gp.width=0;gp.height=GridLayout.LayoutParams.WRAP_CONTENT;
            gp.columnSpec=GridLayout.spec(GridLayout.UNDEFINED,1,1f);
            gp.setMargins(dp(4),dp(5),dp(4),dp(5));
            grid.addView(tile,gp);
        }
        tiles.addView(grid,new LinearLayout.LayoutParams(-1,-2));
    }
    private void pickGame(){
        Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        pick.setType("*/*");
        pick.addCategory(Intent.CATEGORY_OPENABLE);
        pick.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                      Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        try{startActivityForResult(pick,PICK_GAME);}
        catch(Exception e){info.setText("تعذر فتح منتقي الألعاب: "+e.getClass().getSimpleName());}
    }
    private String displayName(Uri uri){
        try(Cursor c=getContentResolver().query(uri,
                new String[]{DocumentsContract.Document.COLUMN_DISPLAY_NAME},
                null,null,null)){
            if(c!=null&&c.moveToFirst())return c.getString(0);
        }catch(Exception ignored){}
        return "";
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request!=PICK_GAME||result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();
        String name=displayName(uri);
        if(!RM11GameLibraryStore.validExe(name)){
            info.setText("اختر ملف Windows بصيغة EXE فقط.");return;
        }
        try{
            String docId=DocumentsContract.getDocumentId(uri);
            java.nio.file.Path path=GameDocumentPathPolicy.resolvePrimary(
                    uri.getAuthority(),docId,name,
                    Environment.getExternalStorageDirectory().toPath());
            File game=path.toFile();
            if(!RM11GameLibraryStore.add(this,game)){
                info.setText("تعذر إضافة EXE. تأكد من وجوده في الذاكرة الرئيسية.");return;
            }
            try{getContentResolver().takePersistableUriPermission(uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(Exception ignored){}
            info.setText("تمت إضافة "+name+" إلى مكتبتك بدون نسخ اللعبة.");
            refresh();
        }catch(Exception ex){
            info.setText("هذا المزوّد لا يتيح ملف EXE كمسار حقيقي للمحاكي. "
                    +"اختره من ذاكرة الهاتف الرئيسية أو من مدير ملفات RM11.");
        }
    }
    private void launchGame(File file){
        if(gameOpening)return;
        if(!RM11GameLibraryStore.allowedPath(file)){
            info.setText("ملف EXE غير موجود أو غير صالح.");return;
        }
        java.nio.file.Path phone=Environment.getExternalStorageDirectory().toPath();
        if(file.toPath().toAbsolutePath().normalize().startsWith(phone)
                &&!PhoneDriveBridge.authorized()){
            new AlertDialog.Builder(this).setTitle("صلاحية الوصول للألعاب")
                .setMessage("لتشغيل EXE مع جميع ملفات اللعبة يحتاج محرك Wine صلاحية قراءة مجلد اللعبة.")
                .setNegativeButton("إلغاء",null)
                .setPositiveButton("فتح الصلاحيات",(d,w)->{
                    Intent request=PhoneDriveBridge.permissionIntent(this);
                    if(request!=null)startActivity(request);
                }).show();return;
        }
        try{
            RuntimeLayout layout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
            NovaWineExeLauncher.Check checked=NovaWineExeLauncher.validate(
                layout,file.toPath(),PhoneDriveBridge.authorized());
            gameOpening=true;
            RM11GameLibraryStore.played(this,checked.path.toString());
            Intent open=new Intent(this,RM11NativeWineActivity.class);
            open.putExtra(RM11NativeWineActivity.EXTRA_DIRECT_GAME_EXE,
                    checked.path.toString());
            startActivity(open);
        }catch(Exception e){
            gameOpening=false;
            info.setText("ما گدرنا نشغل الملف: "+e.getClass().getSimpleName()
                    +" — افتح مدير الملفات وتحقق من موقع اللعبة.");
        }
    }
    @Override protected void onResume(){
        super.onResume();gameOpening=false;
        if(tiles!=null)refresh();
    }
}
