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
import com.rm11.autocore.runtime.VPadBusProbeV49044;
import java.io.File;
import java.util.List;
import java.util.Locale;

/** First-screen game tiles, existing file manager and offline diagnostics kept. */
public final class RM11GameLibraryActivity extends Activity {
    private static final int PICK_GAME=49038, BG=0xff0a0f17;
    private static final int CARD=0xff1a2634, HILITE=0xfff04452;
    private LinearLayout tiles;
    private TextView count,info;
    private int uiProfile;
    private int profileAtCreation;
    private int orientationAtCreation;
    private boolean gameOpening=false;
    private int dp(int px){return Math.round(getResources().getDisplayMetrics().density*px);}
    private GradientDrawable bg(int color,int radius){
        GradientDrawable d=new GradientDrawable();
        d.setColor(color);d.setCornerRadius(dp(radius));
        d.setStroke(dp(1),(RM11UiThemesV49059.accent(uiProfile)&0x00ffffff)|0x55000000);
        return d;
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
        b.setBackground(bg(RM11UiThemesV49059.cardColor(uiProfile),12));
        b.setOnClickListener(listener);
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
        RM11UiThemesV49059.applyOrientation(this);
        uiProfile=RM11UiThemesV49059.selected(this);
        profileAtCreation=uiProfile;
        orientationAtCreation=RM11UiThemesV49059.orientation(this);
        getWindow().setStatusBarColor(RM11UiThemesV49059.background(uiProfile));
        getWindow().setNavigationBarColor(RM11UiThemesV49059.background(uiProfile));
        createUi();
    }
    private void createUi(){
        final int profile=uiProfile;
        boolean portrait=getResources().getConfiguration().orientation
                !=android.content.res.Configuration.ORIENTATION_LANDSCAPE;
        FrameLayout shell=new FrameLayout(this);
        shell.addView(new RM11UiThemesV49059.AnimatedScene(this,profile),
            new FrameLayout.LayoutParams(-1,-1));
        LinearLayout root=vertical();
        root.setPadding(dp(portrait?12:20),dp(9),dp(portrait?12:20),dp(9));
        LinearLayout toolbar=row();
        TextView brand=text("RM11-WinCore",portrait?19:24,Color.WHITE,true);
        toolbar.addView(brand,new LinearLayout.LayoutParams(0,dp(50),1));
        Button appearance=button("✦ المظهر",v->startActivity(
            new Intent(this,RM11AppearanceActivity.class)));
        appearance.setTextColor(RM11UiThemesV49059.accent(profile));
        toolbar.addView(appearance,spacing(portrait?104:143,47,7,0,0,0));
        root.addView(toolbar,spacing(-1,51,0,0,0,4));

        LinearLayout actions=row();
        Button add=button("＋ إضافة EXE",v->pickGame());
        Button files=button("▣ الملفات",v->startActivity(
             new Intent(this,RM11FilesOnlyActivity.class)));
        actions.addView(add,new LinearLayout.LayoutParams(0,dp(49),1));
        LinearLayout.LayoutParams fpos=new LinearLayout.LayoutParams(0,dp(49),1);
        fpos.leftMargin=dp(9);
        actions.addView(files,fpos);
        root.addView(actions,spacing(-1,51,0,0,0,9));

        LinearLayout banner=vertical();
        banner.setBackground(RM11UiThemesV49059.panel(profile,17,
            getResources().getDisplayMetrics().density));
        banner.setPadding(dp(17),dp(11),dp(14),dp(11));
        TextView top=text(
            profile==2?"✦ معرض ألعابك ثلاثي الأبعاد":
            profile==4?"◈ مكتبتك الهولوغرافية":
            profile==5?"▣ مركز ألعاب Windows":
            profile==3?"جاهز للعب؟":
            profile==1?"⚡ اختَر لعبتك وانطلق":
                "✦ مكتبتك السينمائية",portrait?18:22,Color.WHITE,true);
        banner.addView(top,spacing(-1,35,0,0,0,0));
        TextView description=text(RM11UiThemesV49059.DESCRIPTIONS[profile],13,
            0xffbdcfde,false);
        banner.addView(description,spacing(-1,32,0,0,0,3));
        Button probe=button("🎮 فحص يد Windows (DirectInput / XInput)",
            v->launchControllerBusProbe());
        probe.setTextSize(12);
        banner.addView(probe,spacing(-1,40,0,3,0,0));
        root.addView(banner,spacing(-1,-2,0,0,0,8));
        LinearLayout heading=row();
        count=text("مكتبة الألعاب",18,Color.WHITE,true);
        heading.addView(count,new LinearLayout.LayoutParams(0,dp(39),1));
        heading.addView(button("↻ تحديث",v->refresh()),spacing(portrait?90:106,39,4,0,0,0));
        root.addView(heading,spacing(-1,45,0,0,0,5));
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        tiles=vertical();tiles.setPadding(dp(2),dp(4),dp(2),dp(12));
        scroll.addView(tiles);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        info=text("المحاكي جاهز • ملفات EXE الأصلية محفوظة.",12,0xffc5d9e7,false);
        root.addView(info,spacing(-1,29,0,2,0,0));
        shell.addView(root,new FrameLayout.LayoutParams(-1,-1));
        setContentView(shell);
        refresh();
    }
    private void refresh(){
        if(tiles==null)return;
        tiles.removeAllViews();
        List<RM11GameLibraryStore.Game> games=RM11GameLibraryStore.list(this);
        count.setText("مكتبة الألعاب  •  "+games.size());
        if(games.isEmpty()){
            LinearLayout empty=vertical();
            empty.setPadding(dp(22),dp(24),dp(22),dp(23));
            empty.setBackground(RM11UiThemesV49059.panel(uiProfile,16,
                getResources().getDisplayMetrics().density));
            TextView title=text("🎮  مكتبتك جاهزة لاستقبال الألعاب",19,Color.WHITE,true);
            title.setGravity(Gravity.CENTER);
            empty.addView(title);
            TextView hint=text("أضف EXE من الهاتف أو من مدير الملفات — بدون نقل ملفات لعبتك.",13,
                0xffc1d3de,false);
            hint.setGravity(Gravity.CENTER);
            empty.addView(hint,spacing(-1,-2,0,12,0,0));
            tiles.addView(empty,spacing(-1,-2,0,9,0,0));
            return;
        }
        boolean portrait=getResources().getConfiguration().orientation
            !=android.content.res.Configuration.ORIENTATION_LANDSCAPE;
        int cols=RM11UiThemesV49059.libraryColumns(uiProfile,portrait);
        GridLayout grid=new GridLayout(this);grid.setColumnCount(cols);
        grid.setUseDefaultMargins(false);
        for(int i=0;i<games.size();i++){
            RM11GameLibraryStore.Game g=games.get(i);
            File exe=new File(g.path);
            boolean exists=exe.isFile();
            boolean list=cols==1;
            LinearLayout tile=list?row():vertical();
            tile.setBackground(RM11UiThemesV49059.panel(uiProfile,
                uiProfile==3?11:17,getResources().getDisplayMetrics().density));
            tile.setPadding(dp(list?10:12),dp(11),dp(10),dp(10));
            if(uiProfile==2&&!list){
                tile.setElevation(dp(8));
                tile.setRotationY((i%3-1)*2.5f);
            }else if(uiProfile==4){tile.setElevation(dp(5));}
            LinearLayout iconPanel=vertical();
            iconPanel.setGravity(Gravity.CENTER);
            GradientDrawable art=new GradientDrawable(
                 GradientDrawable.Orientation.TL_BR,new int[]{
                 RM11UiThemesV49059.accent(uiProfile),
                 RM11UiThemesV49059.cardColor(uiProfile)});
            art.setCornerRadius(dp(12));
            iconPanel.setBackground(art);
            TextView symbol=text(uiProfile==2?"◈":
                uiProfile==5?"▣":
                uiProfile==1?"⚡":"🎮",list?30:38,Color.WHITE,true);
            symbol.setGravity(Gravity.CENTER);
            iconPanel.addView(symbol);
            if(list){
                tile.addView(iconPanel,new LinearLayout.LayoutParams(dp(76),dp(90)));
            }else{
                tile.addView(iconPanel,spacing(-1,
                    uiProfile==2||uiProfile==4?100:portrait?72:85,0,0,0,9));
            }
            LinearLayout details=vertical();
            if(list)details.setPadding(dp(12),0,dp(8),0);
            TextView title=text(g.title,list?17:16,Color.WHITE,true);
            title.setMaxLines(2);
            title.setGravity(list?Gravity.CENTER_VERTICAL:Gravity.CENTER);
            details.addView(title,spacing(-1,list?39:43,0,0,0,0));
            TextView status=text(exists?"● جاهزة للتشغيل":"● الملف غير موجود",12,
                exists?0xff80eab9:0xffffad86,false);
            status.setGravity(list?Gravity.CENTER_VERTICAL:Gravity.CENTER);
            details.addView(status,spacing(-1,26,0,0,0,5));
            if(list)tile.addView(details,new LinearLayout.LayoutParams(0,-2,1));
            else tile.addView(details,spacing(-1,-2,0,0,0,0));
            LinearLayout buttons=vertical();
            Button play=button(exists?"▶ تشغيل":"إعادة اختيار الملف",v->{
                if(exists)launchGame(exe);
                else info.setText("مسار اللعبة تغير. احذف البطاقة وأضف ملف EXE الجديد.");
            });
            play.setBackground(RM11UiThemesV49059.button(uiProfile,12,
                getResources().getDisplayMetrics().density));
            buttons.addView(play,spacing(-1,43,0,0,0,4));
            Button remove=button("إزالة البطاقة",v->
                new AlertDialog.Builder(this).setTitle("إزالة البطاقة؟")
                    .setMessage("راح نحذف اللعبة من القائمة فقط بدون المساس بملفاتها.")
                    .setNegativeButton("إلغاء",null)
                    .setPositiveButton("إزالة",(dialog,w)->{
                        RM11GameLibraryStore.remove(this,g.path);refresh();
                    }).show());
            remove.setTextSize(11);
            buttons.addView(remove,spacing(-1,35,0,0,0,0));
            if(list)tile.addView(buttons,new LinearLayout.LayoutParams(
                dp(portrait?115:152),-2));
            else tile.addView(buttons,spacing(-1,-2,0,0,0,0));
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
    /** Tests only enumerated Windows controllers; this button is not a gameplay claim. */
    private void launchControllerBusProbe(){
        if(gameOpening)return;
        try{
            RuntimeLayout layout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
            java.nio.file.Path exe=VPadBusProbeV49044.installProbe(this,layout);
            gameOpening=true;
            Intent open=new Intent(this,RM11NativeWineActivity.class);
            open.putExtra(RM11NativeWineActivity.EXTRA_DIRECT_GAME_EXE,exe.toString());
            startActivity(open);
            info.setText("فحص DirectInput وXInput؛ صدّر تقرير اللعبة بعد الفحص.");
        }catch(Exception problem){
            gameOpening=false;
            info.setText("فحص Windows غير جاهز: "+problem.getClass().getSimpleName()
                +" — تأكد من جاهزية Wine C:.");
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
        if(profileAtCreation!=RM11UiThemesV49059.selected(this)
                ||orientationAtCreation!=RM11UiThemesV49059.orientation(this)){
            recreate();
            return;
        }
        if(tiles!=null)refresh();
    }
}
