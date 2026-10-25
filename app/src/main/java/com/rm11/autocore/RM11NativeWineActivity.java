package com.rm11.autocore;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.Context;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.graphics.Rect;
import android.graphics.drawable.GradientDrawable;
import android.widget.PopupWindow;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import com.rm11.autocore.diagnostics.OfflineDiagnosticArchive;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.NativeX11TcpBridge;
import com.rm11.autocore.runtime.NativeXorgLifecycleDiagnostics;
import com.rm11.autocore.runtime.NativeDesktopVisualEvidence;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import com.termux.x11.MainActivity;
import com.termux.x11.RM11NativeX11Service;
import com.termux.x11.RM11NativeDisplayConnector;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * v4 PREVIEW: real X.Org LorieView surface, not legacy Java ScreenView.
 * Start X.Org in a dedicated Android service process and relay the unchanged
 * Wine DISPLAY TCP port to its private AF_UNIX X socket.
 *
 * This version remains a device preview: a successful CI APK build is not
 * proof of readable glyphs or a working Wine desktop on REDMAGIC.
 */
public final class RM11NativeWineActivity extends MainActivity implements ServiceConnection {
    private static final int EXPORT_DIAGNOSTICS=9400;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService wineWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService exportWorker=Executors.newSingleThreadExecutor();
    private NativeX11TcpBridge relay;
    private WineAutoDesktopRunner.Session session;
    private String finalReport="";
    private volatile String lastStatus="جاري بدء خادم X.Org الأصلي...";
    private volatile String lastVisualEvidence="RM11_V410_FRAME_EVIDENCE_NOT_CAPTURED";
    private PopupWindow controlsMenu;
    private Button floatingControls;
    private boolean shuttingDown;
    private boolean wineStarted;
    private boolean nativeServiceRequested;
    private boolean nativeServiceBound;
    private boolean binderEverConnected;
    private volatile IBinder nativeServerBinder;
    private int binderAttempts;
    private final Runnable nativeReadiness=new Runnable() {
        private int attempts;
        @Override public void run() {
            if(shuttingDown || isFinishing() || wineStarted)return;
            connectNativeSurfaceIfReady();
            if(getLorieView()!=null && getLorieView().connected()
                    && getLorieView().getWidth()>0 && getLorieView().getHeight()>0) {
                wineStarted=true;
                // Desktop logical dimensions must equal X.Org's root screen,
                // not physical Android view pixels after UI scaling.
                // The precise X11 root is read after the handshake below.
                final int w=getLorieView().getWidth();
                final int h=getLorieView().getHeight();
                wineWorker.execute(()->launchWhenX11Ready(w,h));
                // Audit actual X11 windows and displayed Android pixels automatically.
                ui.postDelayed(thisActivityVisualAudit(),6000);
                ui.postDelayed(thisActivityVisualAudit(),14000);
                return;
            }
            if(++attempts<40)ui.postDelayed(this,500);
            else {
                boolean dead=binderEverConnected && (nativeServerBinder==null
                        || !nativeServerBinder.isBinderAlive());
                lastStatus=dead
                        ? "خادم X.Org توقف قبل الاتصال؛ تم حفظ تشخيص سبب الخروج."
                        : "تعذر اتصال شاشة Lorie بخادم X.Org؛ تم حفظ تشخيص السبب.";
                showConnectionStatus(lastStatus);
                OfflineDiagnosticJournal.record(RM11NativeWineActivity.this,
                        "v402-native-start-failure",
                        lastStatus+"\n"+NativeXorgLifecycleDiagnostics.snapshot(
                                RM11NativeWineActivity.this));
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        // Configure the *upstream* Termux:X11 renderer before its Activity
        // measures LorieView and before Wine/X.Org are started. Changing
        // fullscreen after super.onCreate would trigger upstream recreation.
        configureImmersiveLorieBeforeCreate();
        super.onCreate(state);
        if(isFinishing())return;
        // Upstream MainActivity can replace setRequestedOrientation from its
        // own forceOrientation preference. Set both for consistent landscape.
        if(prefs!=null && !"landscape".equals(prefs.forceOrientation.get()))
            prefs.forceOrientation.put("landscape");
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        enlargeX11DisconnectedMenu();
        installPreviewControls();
        OfflineDiagnosticJournal.record(this,"v414-immersive-ui-policy",
                "RM11_V414_FULLSCREEN_PROFILE_ACTIVE\\n"
                +"RM11_V414_UPSTREAM_EXTRA_KEYS_HIDDEN_AT_BOOT\\n"
                +"RM11_V414_FLOATING_CONTROLS_ATTACHED\\n"
                +"RM11_V414_LOGICAL_SCREEN_SCALE="+prefs.displayScale.get()+"\\n");
        try {
            File tmp=new File(getFilesDir(),RM11NativeX11Service.TMPDIR_NAME);
            if(!tmp.isDirectory() && !tmp.mkdirs())
                throw new IOException("Cannot create native private TMPDIR");
            relay=new NativeX11TcpBridge();
            relay.start(tmp);
            Intent nativeIntent=new Intent(this,RM11NativeX11Service.class);
            nativeServiceRequested=true;
            startService(nativeIntent);
            nativeServiceBound=bindService(nativeIntent,this,Context.BIND_AUTO_CREATE);
            if(!nativeServiceBound)
                throw new IOException("RM11_V4_NATIVE_XORG_SERVICE_BIND_FAILED");
            lastStatus="خادم X.Org الأصلي طُلب؛ جاري انتظار عرض Lorie...";
            ui.postDelayed(nativeReadiness,350);
        } catch(Exception e) {
            lastStatus="RM11_V4_NATIVE_START_FAILED: "+e;
            OfflineDiagnosticJournal.record(this,"v4-native-start-failure",lastStatus);
            showConnectionStatus("تعذر تشغيل خادم X.Org. افتح التشخيص.");
            Toast.makeText(this,"تعذر تشغيل X.Org؛ افتح التشخيص.",Toast.LENGTH_LONG).show();
        }
    }

    private int dp(float count) {
        return Math.round(getResources().getDisplayMetrics().density*count);
    }

    private android.view.View nativeView(String id) {
        int resource=getResources().getIdentifier(id,"id",getPackageName());
        return resource==0 ? null : findViewById(resource);
    }

    /** Scale Lorie's real disconnected-menu controls without editing
     * or replacing the X.Org surface and AndroidX LorieView itself. */
    private void enlargeX11DisconnectedMenu() {
        android.view.View label=nativeView("textView");
        if(label instanceof TextView) {
            ((TextView)label).setTextSize(26);
            ((TextView)label).setText("جاري الاتصال بخادم Windows...");
            ((TextView)label).setPadding(dp(8),dp(8),dp(8),dp(8));
        }
        for(String id:new String[]{"preferences_button","displays_button",
                "help_button","exit_button"}) {
            android.view.View control=nativeView(id);
            if(control instanceof ImageButton) {
                ViewGroup.LayoutParams params=control.getLayoutParams();
                if(params!=null) {
                    params.width=dp(78);
                    params.height=dp(78);
                    control.setLayoutParams(params);
                }
                control.setPadding(dp(14),dp(14),dp(14),dp(14));
            }
        }
    }

    private void showConnectionStatus(String message) {
        runOnUiThread(()->{
            android.view.View label=nativeView("textView");
            if(label instanceof TextView) {
                ((TextView)label).setText(message);
                ((TextView)label).setTextSize(24);
            }
        });
    }

    /**
     * Native full-screen Lorie preferences are applied *before* the upstream
     * Activity creates its Surface. Uses the upstream actual resolution
     * renderer instead of bitmap scaling; avoids black toolbar margins.
     */
    private void configureImmersiveLorieBeforeCreate() {
        com.termux.x11.LorieApp app=(com.termux.x11.LorieApp)getApplication();
        if(!getPreferences(0).getBoolean("rm11_v414_fullscreen_profile",false)) {
            app.getPrefs(this).displayResolutionMode.put("scaled");
            app.getPrefs(this).get().edit().putInt("displayScale",140).commit();
            app.getPrefs(this).displayStretch.put(true);
            app.getPrefs(this).hideCutout.put(true);
            app.getPrefs(this).adjustHeightForEK.put(false);
            app.getPrefs(this).showAdditionalKbd.put(true);
            getPreferences(0).edit().putBoolean("rm11_v414_fullscreen_profile",true).apply();
        }
        app.getPrefs(this).fullscreen.put(true);
        app.getPrefs(this).forceOrientation.put("landscape");
        app.getPrefs(this).additionalKbdVisible.put(false);
    }

    private GradientDrawable darkPanel(int background) {
        GradientDrawable d=new GradientDrawable();
        d.setColor(background);
        d.setCornerRadius(dp(11));
        return d;
    }

    /**
     * Compact top-right handle. The stock Termux:X11 extra-key bar and
     * Android IME remain available on demand, not always on screen.
     */
    private void installPreviewControls() {
        floatingControls=new Button(this);
        floatingControls.setText("☰");
        floatingControls.setContentDescription("فتح أدوات المحاكي");
        floatingControls.setTextSize(20);
        floatingControls.setAllCaps(false);
        floatingControls.setTextColor(Color.WHITE);
        floatingControls.setPadding(0,0,0,0);
        floatingControls.setMinWidth(0);
        floatingControls.setMinHeight(0);
        floatingControls.setBackground(darkPanel(0xDB172C48));
        floatingControls.setOnClickListener(v->showControlsMenu());
        FrameLayout.LayoutParams p=new FrameLayout.LayoutParams(dp(46),dp(46),
                Gravity.TOP|Gravity.RIGHT);
        p.topMargin=dp(10);
        p.rightMargin=dp(9);
        addContentView(floatingControls,p);
    }

    private void menuAction(LinearLayout box,String title,Runnable action) {
        Button b=new Button(this);
        b.setText(title);
        b.setTextSize(14);
        b.setTextColor(Color.WHITE);
        b.setAllCaps(false);
        b.setMinHeight(0);
        b.setBackground(darkPanel(0xFF243751));
        b.setOnClickListener(v->{
            if(controlsMenu!=null)controlsMenu.dismiss();
            action.run();
        });
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,dp(47));
        p.bottomMargin=dp(6);
        box.addView(b,p);
    }

    private void showControlsMenu() {
        if(shuttingDown||isFinishing())return;
        if(controlsMenu!=null && controlsMenu.isShowing()){
            controlsMenu.dismiss();
            return;
        }
        LinearLayout actions=new LinearLayout(this);
        actions.setOrientation(LinearLayout.VERTICAL);
        actions.setPadding(dp(9),dp(9),dp(9),dp(9));
        actions.setBackground(darkPanel(0xF418293F));
        menuAction(actions,"⌨ لوحة مفاتيح الهاتف",this::toggleKeyboardVisibility);
        menuAction(actions,"⊞ إظهار / إخفاء أزرار Windows",this::toggleExtraKeys);
        menuAction(actions,"▣ تكبير / تصغير حجم النص",this::showDisplayScaleChooser);
        menuAction(actions,"◈ الشاشة والأداء",this::showDisplayInformation);
        menuAction(actions,"☰ التشخيص والسجلات",this::openDiagnostics);
        menuAction(actions,"↩ الرجوع إلى مدير الملفات",()->{
            finish();
        });
        ScrollView scroll=new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.addView(actions);
        int height=Math.min(dp(355),Math.max(dp(230),
                getResources().getDisplayMetrics().heightPixels-dp(60)));
        controlsMenu=new PopupWindow(scroll,dp(268),height,true);
        controlsMenu.setBackgroundDrawable(darkPanel(0xF418293F));
        controlsMenu.setOutsideTouchable(true);
        controlsMenu.setElevation(dp(10));
        controlsMenu.showAtLocation(getLorieView(),Gravity.TOP|Gravity.RIGHT,
                dp(10),dp(62));
    }

    private void showDisplayScaleChooser() {
        final String[] names={"مريح — 125%","أكبر — 140%","كبير — 160%"};
        final int[] values={125,140,160};
        new AlertDialog.Builder(this).setTitle("حجم نوافذ Windows")
                .setSingleChoiceItems(names,
                        prefs.displayScale.get()==125?0:prefs.displayScale.get()==160?2:1,
                        (dialog,index)->{
                            prefs.displayResolutionMode.put("scaled");
                            prefs.get().edit().putInt("displayScale",values[index]).apply();
                            OfflineDiagnosticJournal.record(this,"v414-user-scale",
                                    "RM11_V414_USER_SCALE_NEXT_SESSION="+values[index]);
                            dialog.dismiss();
                            new AlertDialog.Builder(this)
                                .setTitle("تم حفظ الحجم")
                                .setMessage("حجم العرض الجديد يُطبق بصورة كاملة عند فتح سطح مكتب Windows مرة ثانية. النوافذ والملفات ما تتغير.")
                                .setPositiveButton("تم",(d,w)->{}).show();
                        })
                .setNegativeButton("إلغاء",null).show();
    }

    private void showDisplayInformation() {
        float hz=getLorieView()!=null && getLorieView().getDisplay()!=null
                ? getLorieView().getDisplay().getRefreshRate():0f;
        new AlertDialog.Builder(this).setTitle("معلومات الشاشة والأداء")
                .setMessage("وضع الشاشة: ملء الشاشة\\n"
                        +"مقياس عرض Windows: "+prefs.displayScale.get()+"%\\n"
                        +"معدل تحديث شاشة Android: "+Math.round(hz)+" Hz\\n"
                        +"Lorie متصل: "+(getLorieView()!=null && getLorieView().connected())+"\\n"
                        +"معدل FPS الفعلي للألعاب: غير مقاس\\n"
                        +"هذه القائمة لا تغيّر إعدادات Wine أو GPU.")
                .setPositiveButton("حسناً",null).show();
    }

    @Override public void onBackPressed() {
        showControlsMenu();
    }


    @Override public void onServiceConnected(ComponentName name,IBinder binder) {
        binderEverConnected=true;
        nativeServerBinder=binder;
        lastStatus="خادم X.Org أعاد رابط Binder؛ جاري انتظار مقبس العرض...";
        OfflineDiagnosticJournal.record(this,"v4-native-service",
                "RM11_V4_NATIVE_XORG_BOUND_SERVICE_CONNECTED\n");
        ui.removeCallbacks(nativeReadiness);
        ui.post(nativeReadiness);
    }

    @Override public void onServiceDisconnected(ComponentName name) {
        nativeServerBinder=null;
        lastStatus="انقطع خادم X.Org الأصلي. افتح التشخيص.";
        OfflineDiagnosticJournal.record(this,"v4-native-service",
                "RM11_V4_NATIVE_XORG_SERVICE_DISCONNECTED\n");
        showConnectionStatus("خادم X.Org توقف؛ افتح التشخيص لمعرفة سبب الخروج");
        wineWorker.execute(()->OfflineDiagnosticJournal.record(
                RM11NativeWineActivity.this,"v402-service-disconnect",
                NativeXorgLifecycleDiagnostics.snapshot(RM11NativeWineActivity.this)));
    }

    @Override public void onBindingDied(ComponentName name) {
        nativeServerBinder=null;
        lastStatus="RM11_V402_XORG_BINDER_DIED";
        showConnectionStatus("خادم X.Org توقف أثناء تشغيله؛ افتح التشخيص");
        OfflineDiagnosticJournal.record(this,"v402-native-binder-died",lastStatus);
    }

    @Override public void onNullBinding(ComponentName name) {
        nativeServerBinder=null;
        lastStatus="RM11_V402_XORG_SERVICE_RETURNED_NULL_BINDER";
        showConnectionStatus("خادم X.Org فشل في بدء الخدمة؛ افتح التشخيص");
        OfflineDiagnosticJournal.record(this,"v402-native-null-binding",lastStatus);
    }

    private void connectNativeSurfaceIfReady() {
        IBinder binder=nativeServerBinder;
        if(binder==null || !binder.isBinderAlive() || getLorieView()==null
                || getLorieView().connected())return;
        File socket=new File(new File(new File(getFilesDir(),
                RM11NativeX11Service.TMPDIR_NAME),".X11-unix"),"X2");
        if(!socket.exists())return;
        try {
            binderAttempts++;
            boolean linked=RM11NativeDisplayConnector.connectIfNeeded(this,binder);
            if(linked) {
                lastStatus="اتصال شاشة Lorie بخادم X.Org الأصلي نجح.";
                OfflineDiagnosticJournal.record(this,"v4-native-display-binder",
                        "RM11_V4_NATIVE_LORIE_DIRECT_BINDER_CONNECTED\n");
            }
        }catch(RuntimeException e){
            lastStatus="فشل اتصال شاشة Lorie: "+e;
            if(binderAttempts<=3)
                OfflineDiagnosticJournal.record(this,"v4-native-display-binder",
                        "RM11_V4_NATIVE_LORIE_BINDER_ERROR "+e+"\n");
        }
    }

    private Runnable thisActivityVisualAudit() {
        return () -> {
            if(!shuttingDown && !isFinishing())captureNativeVisualEvidence();
        };
    }

    private void captureNativeVisualEvidence() {
        exportWorker.execute(()->{
            final String x11=NativeDesktopVisualEvidence.auditX11();
            ui.post(()->{
                if(shuttingDown || isFinishing())return;
                NativeDesktopVisualEvidence.auditSurface(getLorieView(),ui,pixels->{
                    if(shuttingDown || isFinishing())return;
                    lastVisualEvidence=x11+"\n"+pixels;
                    OfflineDiagnosticJournal.record(RM11NativeWineActivity.this,
                            "v410-real-window-frame-evidence",lastVisualEvidence);
                });
            });
        });
    }

    private int[] readActualX11Screen(int fallbackW,int fallbackH) {
        // X.Org root and LorieView agree on the renderer's logical pixels.
        // Wine's /desktop geometry must use those pixels, not physical DPI.
        try {
            String evidence=NativeDesktopVisualEvidence.auditX11();
            java.util.regex.Matcher m=java.util.regex.Pattern
                    .compile("x11_root_pixels=(\\d+)x(\\d+)").matcher(evidence);
            if(m.find()) {
                int x=Integer.parseInt(m.group(1)),y=Integer.parseInt(m.group(2));
                if(x>=320&&x<=8192&&y>=240&&y<=8192)return new int[]{x,y};
            }
        } catch(RuntimeException ignored){}
        int scale=Math.max(100,Math.min(200,prefs.displayScale.get()));
        int width=(fallbackW*100/scale)/8*8;
        int height=fallbackH*100/scale;
        return new int[]{Math.max(320,width),Math.max(240,height)};
    }

    private void launchWhenX11Ready(int w,int h) {
        WineX11EndpointProbe.Result probe=null;
        for(int i=0;i<36 && !shuttingDown;i++) {
            probe=WineX11EndpointProbe.probeEmbeddedDisplay2();
            if(probe.accepted)break;
            try{Thread.sleep(500);}catch(InterruptedException e){
                Thread.currentThread().interrupt();
                return;
            }
        }
        if(shuttingDown)return;
        if(probe==null || !probe.accepted) {
            lastStatus="RM11_V4_NATIVE_X11_PROTOCOL_NOT_READY";
            showConnectionStatus("فشل اتصال Wine بخادم العرض. افتح التشخيص.");
            finalReport=lastStatus+"\n"
                    +(relay==null?"RELAY_MISSING":relay.diagnostics());
            OfflineDiagnosticJournal.record(this,"v4-native-x11-connect",finalReport);
            return;
        }
        OfflineDiagnosticJournal.record(this,"v4-native-x11-connect",
                "RM11_V4_NATIVE_X11_HANDSHAKE_ACCEPTED\n"
                +(relay==null?"RELAY_MISSING":relay.diagnostics())
                +"RM11_V4_DISPLAY_GLYPHS_NOT_YET_VERIFIED\n");
        WineAutoDesktopRunner.Session current=new WineAutoDesktopRunner.Session();
        session=current;
        lastStatus="X.Org متصل؛ جاري تشغيل Wine...";
        int[] logicalScreen=readActualX11Screen(w,h);
        OfflineDiagnosticJournal.record(this,"v414-desktop-geometry",
                "RM11_V414_XORG_REAL_ROOT="+logicalScreen[0]+"x"+logicalScreen[1]
                +"\\nRM11_V414_ANDROID_VIEW="+w+"x"+h+"\\n");
        finalReport=WineAutoDesktopRunner.run(this,current,
                value->{
                    lastStatus=value;
                    if(value.startsWith("خادم Wine يعمل لكن مدير الملفات خرج.")) {
                        runOnUiThread(()->showWineFailureOverlay(
                                "مدير ملفات Windows توقف، وخادم Wine لا يزال يعمل."));
                    }
                },logicalScreen[0],logicalScreen[1]);
        // Store the failure reason separately: the large Wine server trace
        // may exceed one event's offline journal cap and hide decisive flags.
        boolean wineServerFailed=finalReport.contains("RM11_V304_WINESERVER_EXITED:")
                || finalReport.contains("RM11_V315_EARLY_SERVER_RETRY_EXHAUSTED");
        if(wineServerFailed) {
            String summary="RM11_V405_WINE_SERVER_STOPPED\n"
                    +"X.Org Lorie connection: functioning\n"
                    +"Wine process failure: yes\n"
                    +"Wine window status: unavailable\n"
                    +"Last activity status: "+lastStatus;
            OfflineDiagnosticJournal.record(this,"v405-wine-server-health",summary);
            lastStatus="خادم Wine توقف، بينما X.Org يعمل. افتح التشخيص.";
            runOnUiThread(()->showWineFailureOverlay(lastStatus));
        } else {
            lastStatus="انتهت جلسة Wine؛ راجع التشخيص للتحقق.";
        }
        OfflineDiagnosticJournal.record(this,"v4-native-wine-session",finalReport);
    }

    private void showWineFailureOverlay(String message) {
        if(shuttingDown || isFinishing())return;
        TextView notice=new TextView(this);
        notice.setText(message+"\nاضغط هنا لفتح تقرير Wine");
        notice.setTextSize(19);
        notice.setTextColor(Color.WHITE);
        notice.setBackgroundColor(0xE8212531);
        notice.setGravity(Gravity.CENTER);
        notice.setPadding(dp(24),dp(18),dp(24),dp(18));
        notice.setOnClickListener(v->openDiagnostics());
        FrameLayout.LayoutParams p=new FrameLayout.LayoutParams(
                Math.min(getResources().getDisplayMetrics().widthPixels-dp(50),dp(730)),
                ViewGroup.LayoutParams.WRAP_CONTENT,Gravity.CENTER);
        addContentView(notice,p);
    }

    private void openDiagnostics() {
        String live=session!=null?session.diagnostics():finalReport;
        if(live==null || live.trim().isEmpty())live="لم يبدأ Wine بعد.";
        String details="RM11_V4_NATIVE_XORG_PREVIEW\n"
                +"native service requested: "+nativeServiceRequested+"\n"
                +"native service bound: "+nativeServiceBound+"\n"
                +"service ever connected: "+binderEverConnected+"\n"
                +"service binder alive: "+(nativeServerBinder!=null && nativeServerBinder.isBinderAlive())+"\n"
                +"direct binder attempts: "+binderAttempts+"\n"
                +"Wine launch requested: "+wineStarted+"\n"
                +"Lorie display connected: "+(getLorieView()!=null && getLorieView().connected())+"\n"
                +"X.Org via TCP relay: "+(relay==null?"NOT_STARTED":relay.diagnostics())+"\n"
                +"Windows text visible: NOT VERIFIED BY CI\n"
                +"RM11 v4.0.10 real X11 window/Android Surface audit:\n"+lastVisualEvidence+"\n"
                +"Status: "+lastStatus+"\n\n"
                +NativeXorgLifecycleDiagnostics.snapshot(this)
                +"\n\n"+live;
        OfflineDiagnosticJournal.record(this,"v4-native-live",details);
        TextView txt=new TextView(this);
        txt.setText(details);
        txt.setTextIsSelectable(true);
        txt.setTextSize(12);
        txt.setTextColor(Color.WHITE);
        txt.setPadding(22,16,22,16);
        ScrollView panel=new ScrollView(this);
        panel.setBackgroundColor(0xFF122033);
        panel.addView(txt);
        new AlertDialog.Builder(this)
                .setTitle("RM11 v4 | X.Org + Wine")
                .setView(panel)
                .setPositiveButton("حفظ ZIP",(d,w)->exportZip())
                .setNeutralButton("اختبار الخطوط",(d,w)->{
                    WineAutoDesktopRunner.Session current=session;
                    boolean requested=current!=null && current.requestFontTest();
                    Toast.makeText(this,requested
                            ? "تم طلب اختبار الخطوط المنفصل. سطح المكتب الأصلي سيبقى."
                            : "الاختبار غير متاح الآن أو سبق تشغيله في هذه الجلسة.",
                            Toast.LENGTH_LONG).show();
                    OfflineDiagnosticJournal.record(this,"v407-font-test-user-action",
                            "RM11_V407_USER_CONSENT_FONT_TEST="+requested);
                })
                .setNegativeButton("الرجوع",(d,w)->{})
                .show();
    }

    private void exportZip() {
        Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("application/zip");
        save.putExtra(Intent.EXTRA_TITLE,"RM11-v4-Native-X11-Diagnostics.zip");
        startActivityForResult(save,EXPORT_DIAGNOSTICS);
    }

    @Override protected void onActivityResult(int code,int result,Intent data) {
        super.onActivityResult(code,result,data);
        if(code!=EXPORT_DIAGNOSTICS || result!=RESULT_OK || data==null
                || data.getData()==null)return;
        Uri dest=data.getData();
        exportWorker.execute(()->{
            try(OutputStream out=getContentResolver().openOutputStream(dest)) {
                if(out==null)throw new IOException("ZIP target unavailable");
                OfflineDiagnosticArchive.export(this,out);
                runOnUiThread(()->Toast.makeText(this,
                        "تم حفظ تقرير v4",Toast.LENGTH_LONG).show());
            }catch(Exception e){
                runOnUiThread(()->Toast.makeText(this,
                        "فشل حفظ ZIP: "+e.getClass().getSimpleName(),
                        Toast.LENGTH_LONG).show());
            }
        });
    }

    @Override protected void onDestroy() {
        if(controlsMenu!=null)controlsMenu.dismiss();
        shuttingDown=true;
        ui.removeCallbacks(nativeReadiness);
        if(session!=null)session.close();
        if(relay!=null)relay.close();
        if(nativeServiceBound)unbindService(this);
        if(nativeServiceRequested)stopService(new Intent(this,RM11NativeX11Service.class));
        wineWorker.shutdownNow();
        exportWorker.shutdown();
        super.onDestroy();
    }
}
