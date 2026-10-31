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
import android.widget.ImageView;
import android.widget.HorizontalScrollView;
import android.graphics.drawable.ColorDrawable;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import com.rm11.autocore.runtime.GameDocumentPathPolicy;
import com.rm11.autocore.runtime.R4PrimaryExePathV49076;
import com.rm11.autocore.runtime.R4WitcherExecutableV49072;
import com.rm11.autocore.runtime.R4Vkd3dV49073;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.diagnostics.R4DiagnosticDownloadsV49078;
import com.rm11.autocore.runtime.NovaWineExeLauncher;
import com.rm11.autocore.runtime.KernixGameReadinessV49081;
import com.rm11.autocore.runtime.KernixLaunchAttemptsV49084;
import com.rm11.autocore.runtime.PhoneDriveBridge;
import com.rm11.autocore.runtime.RuntimeLayout;

import java.io.File;
import java.util.List;
import java.util.Locale;

/** First-screen game tiles, existing file manager and offline diagnostics kept. */
public final class RM11GameLibraryActivity extends Activity {
    private static final int PICK_GAME=49038, PICK_COVER=49065, BG=0xff0a0f17;
    private File pendingCoverExe;
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

    private R4CinematicGLViewV49061 world;
    private R4PremiumGalleryV49062 premium;
    private boolean portrait;
    private LinearLayout root;
    private int thumbHeight;
    // Keep the old native preview as an emergency fallback, but every new
    // install opens the same R4 Live UI rather than choosing six skins.
    private boolean useUnifiedR4Home(){
        // KERNIX has one authoritative UI. The previous multi-skin
        // setting must not reopen an obsolete preview on existing installs.
        // Keep old preferences and data untouched for rollback safety.
        return true;
    }
    private void createUi(){
        final int profile=uiProfile;
        // Reference gallery is a dedicated, fully interactive layout. The
        // native Wine/XInput launch path is the same used by other skins.
        if(useUnifiedR4Home()){
            info=text("",12,0xffe8c98f,false);
            premium=new R4PremiumGalleryV49062(this,new R4PremiumGalleryV49062.Actions(){
                @Override public void launch(File exe){launchGame(exe);}
                @Override public void add(){pickGame();}
                @Override public void diagnostics(){showGeneralDiagnostics();}
                @Override public void gameDiagnostics(File exe){
                    exportGameDiagnostics(exe);
                }
                @Override public void files(){
                    startActivity(new Intent(RM11GameLibraryActivity.this,RM11FilesOnlyActivity.class));
                }
                @Override public void appearance(){
                    startActivity(new Intent(RM11GameLibraryActivity.this,RM11AppearanceActivity.class));
                }
                @Override public void orientation(){selectScreenOrientation();}
                @Override public void cover(File exe){chooseGameCover(exe);}
            });
            getWindow().setStatusBarColor(0xff081319);
            getWindow().setNavigationBarColor(0xff081319);
            setContentView(premium);
            return;
        }
        portrait=getResources().getConfiguration().orientation
            !=android.content.res.Configuration.ORIENTATION_LANDSCAPE;
        int screenHeight=getResources().getConfiguration().screenHeightDp;
        thumbHeight=portrait?150:Math.max(72,Math.min(108,screenHeight-224));
        getWindow().setStatusBarColor(0xff070b15);
        getWindow().setNavigationBarColor(0xff070b15);
        FrameLayout shell=new FrameLayout(this);
        // Real 3D geometry rendered by Android GPU. Worker pauses on game launch.
        try {
            world=new R4CinematicGLViewV49061(this,profile);
            shell.addView(world,new FrameLayout.LayoutParams(-1,-1));
        } catch(RuntimeException unsupported){
            world=null;
            shell.addView(new R4WorldSceneV49060(this,profile),
                new FrameLayout.LayoutParams(-1,-1));
        }
        root=vertical();
        root.setPadding(dp(portrait?13:17),dp(8),dp(portrait?13:17),dp(5));
        if(android.os.Build.VERSION.SDK_INT>=30){
            root.setOnApplyWindowInsetsListener((view,insets)->{
                android.graphics.Insets bar=insets.getInsets(
                    android.view.WindowInsets.Type.systemBars()|
                    android.view.WindowInsets.Type.displayCutout());
                view.setPadding(dp(portrait?13:17)+bar.left,dp(7)+bar.top,
                    dp(portrait?13:17)+bar.right,dp(5)+bar.bottom);
                return insets;
            });
        }
        LinearLayout bar=row();
        TextView brand=text("KERNIX",portrait?19:23,Color.WHITE,true);
        bar.addView(brand,new LinearLayout.LayoutParams(0,dp(46),1));
        Button menu=button("☰",v->showLauncherMenu());
        menu.setTextSize(23);
        menu.setBackground(RM11UiThemesV49059.panel(profile,13,
            getResources().getDisplayMetrics().density));
        bar.addView(menu,spacing(64,44,7,0,0,0));
        root.addView(bar,spacing(-1,47,0,0,0,4));
        LinearLayout hero=vertical();
        hero.setPadding(dp(12),0,dp(8),0);
        TextView heading=text(
            profile==2?"✦ عالم الألعاب ثلاثي الأبعاد":
            profile==4?"◈ عالم الألعاب الهولوغرافي":
            profile==5?"▣ عالم الألعاب المكتبي":
            profile==3?"◈ عالم الألعاب الطبيعي":
            profile==1?"⚡ عالم الألعاب القتالي":
            "✦ عالم الألعاب السينمائي",portrait?19:22,Color.WHITE,true);
        hero.addView(heading,spacing(-1,portrait?44:38,0,0,0,0));
        TextView hint=text(portrait?"اختر لعبة من مكتبتك وابدأ":
            "استمتع بمكتبتك وتبديل الألعاب مباشرة",12,0xffc6d9e5,false);
        hero.addView(hint,spacing(-1,25,0,0,0,0));
        int heroHeight=portrait?72:screenHeight<340?44:56;
        root.addView(hero,spacing(-1,heroHeight,0,0,0,0));
        // The 3D world gets real screen space, rather than being hidden by
        // enormous decorative banners and controller diagnostic buttons.
        if(!portrait)root.addView(new View(this),new LinearLayout.LayoutParams(-1,0,1));
        LinearLayout headingLine=row();
        count=text("مكتبة الألعاب",portrait?20:17,Color.WHITE,true);
        headingLine.addView(count,new LinearLayout.LayoutParams(0,dp(35),1));
        Button refreshBtn=button("↻",v->refresh());
        refreshBtn.setTextSize(20);
        headingLine.addView(refreshBtn,spacing(58,38,0,0,0,0));
        root.addView(headingLine,spacing(-1,40,0,0,0,4));
        ScrollView scroll=new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.setVerticalScrollBarEnabled(false);
        tiles=vertical();tiles.setPadding(dp(2),0,dp(2),dp(6));
        scroll.addView(tiles);
        if(portrait)root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        else root.addView(scroll,spacing(-1,
            Math.max(142,Math.min(222,screenHeight-heroHeight-116)),
            0,0,0,0));
        info=text("",11,0xffbfdfeb,false);
        info.setMaxLines(2);
        root.addView(info,spacing(-1,portrait?30:22,0,0,0,0));
        shell.addView(root,new FrameLayout.LayoutParams(-1,-1));
        setContentView(shell);
        if(android.os.Build.VERSION.SDK_INT>=30)root.requestApplyInsets();
        // After the UI is rebuilt the game shelf is entirely inside the viewport.
        refresh();
    }
    private void showLauncherMenu(){
        final int profile=uiProfile;
        final android.app.Dialog dialog=new android.app.Dialog(this);
        LinearLayout sheet=vertical();
        sheet.setPadding(dp(15),dp(18),dp(15),dp(15));
        sheet.setBackground(RM11UiThemesV49059.panel(profile,20,
            getResources().getDisplayMetrics().density));
        TextView heading=text("KERNIX  •  القائمة",20,Color.WHITE,true);
        sheet.addView(heading,spacing(-1,52,0,0,0,10));
        sheet.addView(menuButton("＋ إضافة لعبة EXE",()->{
            dialog.dismiss();pickGame();
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("▣ مستكشف الملفات",()->{
            dialog.dismiss();
            startActivity(new Intent(this,RM11FilesOnlyActivity.class));
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("🧪 التشخيص العام",()->{
            dialog.dismiss();showGeneralDiagnostics();
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("✦ المظهر وعوالم 3D",()->{
            dialog.dismiss();
            startActivity(new Intent(this,RM11AppearanceActivity.class));
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("↻ اتجاه الشاشة",()->{
            dialog.dismiss();selectScreenOrientation();
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("⟳ تحديث مكتبة الألعاب",()->{
            dialog.dismiss();refresh();
        }),spacing(-1,51,0,0,0,7));
        sheet.addView(menuButton("✕ إغلاق القائمة",dialog::dismiss),
            spacing(-1,51,0,0,0,7));
        dialog.setContentView(sheet);
        android.view.Window window=dialog.getWindow();
        if(window!=null){
            window.setBackgroundDrawableResource(android.R.color.transparent);
            window.setLayout(dp(portrait?298:330),-1);
            window.setGravity(Gravity.END|Gravity.TOP);
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            android.view.WindowManager.LayoutParams p=window.getAttributes();
            p.dimAmount=.35f;window.setAttributes(p);
        }
        dialog.show();
        if(window!=null){
            window.setLayout(dp(portrait?298:330),-1);
            window.setGravity(Gravity.END|Gravity.TOP);
            sheet.setTranslationX(dp(80));sheet.setAlpha(.4f);
            sheet.animate().translationX(0).alpha(1).setDuration(270).start();
        }
    }
    private Button menuButton(String text,Runnable action){
        Button b=button(text,v->action.run());
        b.setTextSize(15);
        return b;
    }
    private void selectScreenOrientation(){
        String[] names={"تلقائي حسب حساس الجهاز","عمودي ثابت","أفقي ثابت"};
        new AlertDialog.Builder(this).setTitle("اتجاه واجهة R4")
            .setSingleChoiceItems(names,RM11UiThemesV49059.orientation(this),
                (dialog,index)->{
                    RM11UiThemesV49059.setOrientation(this,index);
                    dialog.dismiss();
                    RM11UiThemesV49059.applyOrientation(this);
                    recreate();
                }).setNegativeButton("إلغاء",null).show();
    }
    private void refresh(){
        if(premium!=null){premium.refresh();return;}
        if(tiles==null)return;
        tiles.removeAllViews();
        List<RM11GameLibraryStore.Game> games=RM11GameLibraryStore.list(this);
        count.setText("مكتبة الألعاب  •  "+games.size());
        if(games.isEmpty()){
            TextView empty=text("ما أضفت ألعاب بعد.\nمن ☰ اختار «إضافة لعبة EXE».",
                17,Color.WHITE,true);
            empty.setGravity(Gravity.CENTER);
            empty.setBackground(RM11UiThemesV49059.panel(uiProfile,16,
                getResources().getDisplayMetrics().density));
            tiles.addView(empty,spacing(-1,portrait?190:130,0,8,0,0));
            return;
        }
        if(!portrait){
            HorizontalScrollView horizontal=new HorizontalScrollView(this);
            horizontal.setHorizontalScrollBarEnabled(false);
            LinearLayout gameRow=row();
            gameRow.setPadding(dp(3),0,dp(8),dp(1));
            for(int i=0;i<games.size();i++){
                LinearLayout tile=gameTile(games.get(i),i,true);
                LinearLayout.LayoutParams p=spacing(155,-2,5,3,5,5);
                gameRow.addView(tile,p);
            }
            horizontal.addView(gameRow);
            tiles.addView(horizontal,spacing(-1,-2,0,0,0,0));
        }else{
            GridLayout grid=new GridLayout(this);
            grid.setColumnCount(2);
            for(int i=0;i<games.size();i++){
                LinearLayout card=gameTile(games.get(i),i,false);
                GridLayout.LayoutParams p=new GridLayout.LayoutParams();
                p.width=0;p.height=GridLayout.LayoutParams.WRAP_CONTENT;
                p.columnSpec=GridLayout.spec(GridLayout.UNDEFINED,1,1f);
                p.setMargins(dp(5),dp(5),dp(5),dp(5));
                grid.addView(card,p);
            }
            tiles.addView(grid,spacing(-1,-2,0,0,0,0));
        }
    }
    private LinearLayout gameTile(RM11GameLibraryStore.Game game,int index,boolean landscape){
        File exe=new File(game.path);
        boolean available=exe.isFile();
        LinearLayout tile=vertical();
        tile.setBackground(RM11UiThemesV49059.panel(uiProfile,15,
            getResources().getDisplayMetrics().density));
        tile.setPadding(dp(6),dp(6),dp(6),dp(8));
        tile.setElevation(dp(uiProfile==2?11:5));
        if(uiProfile==2&&!landscape){
            tile.setCameraDistance(dp(8500));
            tile.setRotationY((index%4-1.5f)*2.5f);
        }
        FrameLayout poster=new FrameLayout(this);
        GradientDrawable back=new GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            new int[]{RM11UiThemesV49059.accent(uiProfile),
                RM11UiThemesV49059.cardColor(uiProfile)});
        back.setCornerRadius(dp(12));
        poster.setBackground(back);
        poster.setClipToOutline(true);
        ImageView artwork=new ImageView(this);
        artwork.setScaleType(ImageView.ScaleType.CENTER_CROP);
        artwork.setTag(exe.getAbsolutePath());
        poster.addView(artwork,new FrameLayout.LayoutParams(-1,-1));
        TextView placeholder=text("R4\nPC GAMING",landscape?13:18,
            Color.WHITE,true);
        placeholder.setGravity(Gravity.CENTER);
        poster.addView(placeholder,new FrameLayout.LayoutParams(-1,-1));
        tile.addView(poster,spacing(-1,landscape?thumbHeight:146,0,0,0,5));
        TextView title=text(game.title,landscape?12:15,Color.WHITE,true);
        title.setGravity(Gravity.CENTER);
        title.setMaxLines(1);
        title.setEllipsize(android.text.TextUtils.TruncateAt.END);
        tile.addView(title,spacing(-1,landscape?27:34,0,0,0,1));
        Button play=button(available?"▶ تشغيل":"غير متوفرة",v->{
            if(available)launchGame(exe);
            else info.setText("ملف اللعبة غير موجود. أضف المسار الصحيح من جديد.");
        });
        play.setEnabled(available);
        play.setTextSize(landscape?12:14);
        play.setBackground(RM11UiThemesV49059.button(uiProfile,10,
            getResources().getDisplayMetrics().density));
        tile.addView(play,spacing(-1,landscape?33:41,0,1,0,0));
        tile.setOnLongClickListener(v->{
            new AlertDialog.Builder(this).setTitle(game.title)
                .setItems(new String[]{"تشغيل","إزالة من المكتبة فقط"},(d,idx)->{
                    if(idx==0){if(available)launchGame(exe);}
                    else new AlertDialog.Builder(this).setTitle("إزالة البطاقة؟")
                        .setMessage("ملفات اللعبة نفسها تبقى محفوظة.")
                        .setNegativeButton("إلغاء",null)
                        .setPositiveButton("إزالة",(dd,w)->{
                            RM11GameLibraryStore.remove(this,game.path);refresh();
                        }).show();
                }).show();
            return true;
        });
        if(available)R4GameMetadataV49060.load(this,exe,(name,bitmap,source)->{
            if(!exe.getAbsolutePath().equals(artwork.getTag()))return;
            if(bitmap!=null){artwork.setImageBitmap(bitmap);placeholder.setVisibility(View.GONE);}
            if(name!=null&&!name.trim().isEmpty())title.setText(name);
        });
        if(RM11UiThemesV49059.motion(this)&&index<8){
            tile.setAlpha(.1f);
            tile.setTranslationY(dp(12));
            tile.animate().alpha(1).translationY(0)
                .setDuration(340).setStartDelay(index*50L).start();
        }
        return tile;
    }

    private void chooseGameCover(File exe){
        if(exe==null||!RM11GameLibraryStore.validExe(exe.getName()))return;
        pendingCoverExe=exe;
        Intent chooser=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        chooser.setType("image/*");
        chooser.addCategory(Intent.CATEGORY_OPENABLE);
        chooser.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try{startActivityForResult(chooser,PICK_COVER);}
        catch(Exception e){
            pendingCoverExe=null;
            Toast.makeText(this,"تعذر فتح منتقي الصور",Toast.LENGTH_SHORT).show();
        }
    }
    private void exportGameDiagnostics(File exe){
        if(exe==null || !RM11GameLibraryStore.validExe(exe.getName())){
            showGameMessage("اختار لعبة من المكتبة أولاً.");return;
        }
        KernixGameReadinessV49081.Result readiness=
            KernixGameReadinessV49081.inspect(exe.toPath());
        OfflineDiagnosticJournal.record(this,"kernix-game-readiness",
            readiness.evidence());
        OfflineDiagnosticJournal.record(this,"kernix-last-launch-attempt",
            "KERNIX_ATTEMPT_SNAPSHOT="+
            KernixLaunchAttemptsV49084.snapshot(this,exe).toString());
        OfflineDiagnosticJournal.record(this,"kernix-game-diagnostics",
            "KERNIX_SELECTED_EXE_NAME="+exe.getName()+"\n"
            +"KERNIX_GAME_SOURCE_READABLE="+
                (exe.getParentFile()!=null&&exe.getParentFile().canRead())+"\n"
            +"KERNIX_DIAGNOSTIC_SCOPE=SELECTED_LIBRARY_GAME\n"
            +"KERNIX_GAME_FILES_MODIFIED=false");
        com.rm11.autocore.diagnostics.R4DiagnosticDownloadsV49078.save(this,true);
    }
    private void showGeneralDiagnostics(){
        // Main-menu diagnostics are available without starting Windows or
        // selecting a game. Same offline archive as the in-game diagnosis.
        String version="UNAVAILABLE";
        try{
            android.content.pm.PackageInfo info=
                getPackageManager().getPackageInfo(getPackageName(),0);
            version=info.versionName;
        }catch(Exception ignored){}
        final String details="الإصدار: "+version+"\n"
            +"تشخيص عام للمحاكي: Wine وFEX وX11 وVulkan "
            +"وسجلات الألعاب السابقة إذا كانت موجودة.\n"
            +"الحفظ مباشرة في Download، بدون فتح آخر مجلد لعبة.\n"
            +"هذا الفحص ما يشغّل أي لعبة ولا يغيّر ملفاتها.";
        new AlertDialog.Builder(this)
            .setTitle("🧪 التشخيص العام — KERNIX")
            .setMessage(details)
            .setPositiveButton("حفظ ZIP في Download",
                (dialog,which)->R4DiagnosticDownloadsV49078.save(this,false))
            .setNegativeButton("إغلاق",null)
            .show();
    }
    private void showGameMessage(String message){
        if(info!=null)info.setText(message);
        Toast.makeText(this,message,Toast.LENGTH_LONG).show();
    }
    private void explainWitcherDx12(){
        new AlertDialog.Builder(this)
            .setTitle("The Witcher 3 — إصدار DirectX 12 فقط")
            .setMessage("فحصنا مجلد اللعبة: ما لقينا ملف DirectX 11 في bin/x64/witcher3.exe. "
                +"الإصدار الحالي يستخدم DirectX 12 ويحتاج VKD3D-Proton مع Vulkan عتادي متوافق. "
                +"حالياً إذا حزمة VKD3D-Proton أو مسار Vulkan غير متوفرة، نمنع التشغيل بدون مكوّناتها. "
                +"ملفات لعبتك ما تغيرت.")
            .setPositiveButton("فهمت",null).show();
    }
    private void pickGame(){
        // Android DocumentsUI may resume last directory. With user-granted
        // file access, our ONE EXE picker starts from primary storage ROOT
        // on every invocation, never from previously added game folders.
        if(PhoneDriveBridge.authorized()){
            try{
                R4PrimaryExePickerV49076.open(this,this::addSelectedGame);
                OfflineDiagnosticJournal.record(this,"v49076-game-file-picker",
                    "R4_V49076_PICKER=PRIMARY_STORAGE_ROOT\n"
                    +"R4_V49076_REMEMBER_PREVIOUS_FOLDER=false\n"
                    +"R4_V49076_ONLY_ONE_EXE_IMPORT_ACTION=true");
                return;
            }catch(Exception e){
                showGameMessage("تعذر فتح المتصفح الداخلي: "
                    +e.getClass().getSimpleName());
            }
        }else{
            new AlertDialog.Builder(this)
                .setTitle("صلاحية قراءة مجلدات الألعاب")
                .setMessage("حتى المحاكي يقرأ كل ملفات اللعبة، فعّل صلاحية جميع الملفات. "
                    +"بعدها زر إضافة لعبة يفتح التخزين الداخلي من البداية.")
                .setPositiveButton("منح الصلاحية",(d,w)->{
                    Intent i=PhoneDriveBridge.permissionIntent(this);
                    if(i!=null)startActivity(i);
                })
                .setNegativeButton("فتح ملفات Android",(d,w)->pickGameFromDocuments())
                .show();
            return;
        }
        pickGameFromDocuments();
    }
    private void pickGameFromDocuments(){
        Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        pick.setType("*/*");
        pick.addCategory(Intent.CATEGORY_OPENABLE);
        pick.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION |
                      Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        // On some Android DocumentsUI builds this is advisory only.
        try{
            Uri root=DocumentsContract.buildDocumentUri(
                "com.android.externalstorage.documents","primary:");
            pick.putExtra(DocumentsContract.EXTRA_INITIAL_URI,root);
        }catch(Exception ignored){}
        try{startActivityForResult(pick,PICK_GAME);}
        catch(Exception e){showGameMessage(
            "تعذر فتح نافذة اختيار EXE: "+e.getClass().getSimpleName());}
    }
    /** Import records the canonical original EXE and its readable source
     * folder, never just the basename and never a copy of the game. */
    private void addSelectedGame(File path){
        try{
            java.nio.file.Path phoneRoot=Environment.getExternalStorageDirectory().toPath();
            if(path==null || !R4PrimaryExePathV49076.validExe(phoneRoot,path.toPath())){
                showGameMessage("ملف EXE مو موجود أو خارج التخزين الداخلي.");return;
            }
            R4WitcherExecutableV49072.Selection selected=
                R4WitcherExecutableV49072.resolve(path);
            File game=selected.executable;
            if(!RM11GameLibraryStore.add(this,game)){
                showGameMessage("تعذر إضافة EXE. تأكد من وجود اللعبة بذاكرة الهاتف الرئيسية.");return;
            }
            refresh();
            showGameMessage("انضافت اللعبة للمكتبة تلقائياً: "+game.getName());
            OfflineDiagnosticJournal.record(this,"v49072-game-import",
                "R4_V49072_SINGLE_EXE_PICKER=true\n"
                +"R4_V49072_WITCHER_EXE_POLICY="+selected.status+"\n"
                +"R4_V49072_ORIGINAL_FILES_UNCHANGED=true");
            OfflineDiagnosticJournal.record(this,"v49076-full-game-source",
                R4PrimaryExePathV49076.sourceEvidence(phoneRoot,game.toPath()));
            if(selected.blocked() && !R4Vkd3dV49073.hasBundledProvider(this))
                explainWitcherDx12();
        }catch(Exception ex){
            showGameMessage("تعذر قراءة ملف اللعبة أو مجلدها: "
                +ex.getClass().getSimpleName());
        }
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
        if(request==PICK_COVER){
            File target=pendingCoverExe;pendingCoverExe=null;
            if(result!=RESULT_OK||data==null||data.getData()==null||target==null)return;
            final Uri art=data.getData();
            new Thread(()->{
                boolean ok=R4GameMetadataV49060.saveCustomCover(
                    getApplicationContext(),target,art);
                runOnUiThread(()->{
                    Toast.makeText(this,ok?"تم حفظ غلاف اللعبة":"تعذّر قراءة الصورة",
                        Toast.LENGTH_SHORT).show();
                    if(ok)refresh();
                });
            },"r4-save-custom-cover").start();
            return;
        }
        if(request!=PICK_GAME||result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();
        String name=displayName(uri);
        if(!RM11GameLibraryStore.validExe(name)){
            showGameMessage("اختار ملف لعبة Windows بصيغة EXE فقط.");return;
        }
        try{
            String docId=DocumentsContract.getDocumentId(uri);
            java.nio.file.Path path=GameDocumentPathPolicy.resolvePrimary(
                    uri.getAuthority(),docId,name,
                    Environment.getExternalStorageDirectory().toPath());
            try{getContentResolver().takePersistableUriPermission(uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION);}catch(Exception ignored){}
            addSelectedGame(path.toFile());
        }catch(Exception ex){
            showGameMessage("اختار ملف EXE من (التخزين الداخلي) بنافذة الملفات. "
                    +"المزوّد المختار ما يوفر مساراً مباشراً يحتاجه Wine.");
        }
    }
    private void launchGame(File file){
        if(gameOpening)return;
        // Keep ORIGINAL library identity separate from the resolved Witcher/
        // alternate PE path so the library timestamp and status stay together.
        final File originalLibraryExe=file;
        KernixGameReadinessV49081.Result readiness=
            KernixGameReadinessV49081.inspect(file==null?null:file.toPath());
        OfflineDiagnosticJournal.record(this,"kernix-prelaunch-readiness",
            readiness.evidence());
        if(!readiness.canAttempt){
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                KernixLaunchAttemptsV49084.SOURCE_BLOCKED);
            showGameMessage("تعذر الوصول لمصدر اللعبة: "+readiness.detail);
            return;
        }
        // Asset warnings are advisory only. Never break a game that has
        // previously launched on this device based on unproven hints.
        R4WitcherExecutableV49072.Selection selected=
                R4WitcherExecutableV49072.resolve(file);
        if(selected.blocked() && !R4Vkd3dV49073.hasBundledProvider(this)){
            OfflineDiagnosticJournal.record(this,"v49072-witcher-dx12-block",
                "R4_V49072_WITCHER_VKD3D_REQUIRED_NOT_INSTALLED=true\n"
                +"R4_V49072_NO_FALSE_DXVK_D3D12_CLAIM=true");
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                KernixLaunchAttemptsV49084.COMPONENT_BLOCKED);
            explainWitcherDx12();
            return;
        }
        file=selected.executable;
        if(!RM11GameLibraryStore.allowedPath(file)){
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                KernixLaunchAttemptsV49084.SOURCE_BLOCKED);
            showGameMessage("ملف EXE غير موجود أو غير صالح.");return;
        }
        java.nio.file.Path phone=Environment.getExternalStorageDirectory().toPath();
        if(file.toPath().toAbsolutePath().normalize().startsWith(phone)
                &&!PhoneDriveBridge.authorized()){
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                KernixLaunchAttemptsV49084.PERMISSION_REQUIRED);
            new AlertDialog.Builder(this).setTitle("صلاحية الوصول للألعاب")
                .setMessage("لتشغيل EXE مع جميع ملفات اللعبة يحتاج محرك Wine صلاحية قراءة مجلد اللعبة.")
                .setNegativeButton("إلغاء",null)
                .setPositiveButton("فتح الصلاحيات",(d,w)->{
                    Intent request=PhoneDriveBridge.permissionIntent(this);
                    if(request!=null)startActivity(request);
                }).show();return;
        }
        boolean activityDispatchFailed=false;
        try{
            RuntimeLayout layout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
            NovaWineExeLauncher.Check checked=NovaWineExeLauncher.validate(
                layout,file.toPath(),PhoneDriveBridge.authorized());
            gameOpening=true;
            Intent open=new Intent(this,RM11NativeWineActivity.class);
            open.putExtra(RM11NativeWineActivity.EXTRA_DIRECT_GAME_EXE,
                    checked.path.toString());
            try{
                startActivity(open);
            }catch(RuntimeException dispatchError){
                activityDispatchFailed=true;
                throw dispatchError;
            }
            // Only an Android Activity handoff. Not PE process success, no GPU proof.
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                KernixLaunchAttemptsV49084.ACTIVITY_DISPATCHED);
            RM11GameLibraryStore.played(this,originalLibraryExe.getCanonicalPath());
            OfflineDiagnosticJournal.record(this,"kernix-launch-handoff",
                "KERNIX_NATIVE_ACTIVITY_DISPATCHED=true\n"
                +"KERNIX_GAMEPLAY_STARTED=UNVERIFIED\n"
                +"KERNIX_FRAME_PRESENTED=UNVERIFIED");
        }catch(Exception e){
            gameOpening=false;
            KernixLaunchAttemptsV49084.record(this,originalLibraryExe,
                activityDispatchFailed?KernixLaunchAttemptsV49084.ACTIVITY_FAILED:
                    KernixLaunchAttemptsV49084.VALIDATION_FAILED);
            showGameMessage("ما گدرنا نشغل الملف: "+e.getClass().getSimpleName()
                    +" — تحقق من مسار EXE وصلاحية الهاتف.");
        }
    }
    @Override protected void onPause(){
        if(world!=null)world.stop();
        if(premium!=null)premium.pause();
        super.onPause();
    }
    @Override protected void onResume(){
        super.onResume();
        if(world!=null)world.start();
        if(premium!=null)premium.resume();
        gameOpening=false;
        if(profileAtCreation!=RM11UiThemesV49059.selected(this)
                ||orientationAtCreation!=RM11UiThemesV49059.orientation(this)){
            recreate();
            return;
        }
        if(tiles!=null)refresh();
    }
    @Override protected void onDestroy(){
        if(premium!=null){premium.dispose();premium=null;}
        super.onDestroy();
    }
}
