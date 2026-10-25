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
import android.os.Handler;
import android.os.Looper;
import android.os.Build;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.WindowManager;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import android.widget.PopupWindow;
import android.graphics.drawable.GradientDrawable;
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
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.PhoneDriveBridge;
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
    private volatile String lastViewportEvidence="RM11_V414_VIEWPORT_NOT_MEASURED";
    private volatile String lastPhoneDriveEvidence="RM11_V414_PHONE_DRIVE_NOT_CHECKED";
    private boolean keysPanelVisible;
    private volatile boolean winefileMaximizeScheduled;
    private PopupWindow controlPopup;
    private OnBackInvokedCallback backControlsCallback;
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
        super.onCreate(state);
        if(isFinishing())return;
        // Upstream MainActivity can replace setRequestedOrientation from its
        // own forceOrientation preference. Set both for consistent landscape.
        if(prefs!=null && !"landscape".equals(prefs.forceOrientation.get()))
            prefs.forceOrientation.put("landscape");
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        if(prefs!=null) {
            prefs.fullscreen.put(true);
            prefs.hideCutout.put(true);
            prefs.showAdditionalKbd.put(true);
            prefs.additionalKbdVisible.put(false);
            prefs.displayResolutionMode.put("scaled");
            prefs.putInt("displayScale",150);
            prefs.displayStretch.put(true);
        }
        applyRm11ImmersiveScreen();
        if(getLorieView()!=null) getLorieView().triggerCallback();
        enlargeX11DisconnectedMenu();
        installBackOnlyControls();
        RuntimeLayout phoneLayout=new RuntimeLayout(getFilesDir().toPath(),
                new File(getApplicationInfo().nativeLibraryDir).toPath());
        lastPhoneDriveEvidence=PhoneDriveBridge.mountIfAuthorized(this,phoneLayout);
        OfflineDiagnosticJournal.record(this,"v414-phone-drive",lastPhoneDriveEvidence);
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


    private void applyRm11ImmersiveScreen() {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN);
        if(Build.VERSION.SDK_INT>=28) {
            WindowManager.LayoutParams attributes=getWindow().getAttributes();
            attributes.layoutInDisplayCutoutMode=Build.VERSION.SDK_INT>=30
                    ? WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS
                    : WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
            getWindow().setAttributes(attributes);
        }
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                |View.SYSTEM_UI_FLAG_LAYOUT_STABLE|View.SYSTEM_UI_FLAG_FULLSCREEN
                |View.SYSTEM_UI_FLAG_HIDE_NAVIGATION|View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY);
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if(focused)applyRm11ImmersiveScreen();
    }

    private Button controlAction(String caption,Runnable action) {
        Button b=new Button(this);
        b.setText(caption);
        b.setTextSize(15);
        b.setTextColor(Color.WHITE);
        b.setAllCaps(false);
        b.setBackgroundColor(0xff263a54);
        b.setMinHeight(dp(47));
        b.setOnClickListener(v->{
            if(controlPopup!=null)controlPopup.dismiss();
            action.run();
        });
        return b;
    }

    private void installBackOnlyControls() {
        // REDMAGIC Back gesture / physical Back key opens controls.
        // Leave ZERO permanently floating UI over the Windows surface.
        if(getTerminalToolbarViewPager()!=null)
            getTerminalToolbarViewPager().setVisibility(View.GONE);
        if(Build.VERSION.SDK_INT>=33) {
            backControlsCallback=()->showBackControls();
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                    OnBackInvokedDispatcher.PRIORITY_DEFAULT,backControlsCallback);
        }
        OfflineDiagnosticJournal.record(this,"v415-controls",
                "RM11_V415_MENU_TRIGGER=ANDROID_BACK_ONLY\n"
                +"RM11_V415_EXTRA_KEYS_BAR_DEFAULT=HIDDEN");
    }

    private void showBackControls() {
        if(controlPopup!=null && controlPopup.isShowing()) {
            controlPopup.dismiss();
            return;
        }
        toggleControlMenu();
    }

    private void toggleControlMenu() {
        if(controlPopup!=null&&controlPopup.isShowing()) {
            controlPopup.dismiss();
            return;
        }
        LinearLayout content=new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(8),dp(8),dp(8),dp(8));
        content.setBackgroundColor(0xf0101f34);
        content.addView(controlAction("⌨  فتح لوحة المفاتيح",()->{
            if(getLorieView()!=null) {
                getLorieView().requestFocus();
                getLorieView().setKeyboardVisible(true);
            }
        }));
        content.addView(controlAction(keysPanelVisible?"إخفاء اختصارات التحكم":
                "إظهار اختصارات التحكم",()->{
            keysPanelVisible=!keysPanelVisible;
            if(prefs!=null) {
                prefs.additionalKbdVisible.put(keysPanelVisible);
                toggleExtraKeys(keysPanelVisible,true);
            }
            OfflineDiagnosticJournal.record(this,"v414-controls",
                    "RM11_V414_EXTRA_KEYS_VISIBLE="+keysPanelVisible);
        }));
        content.addView(controlAction("ESC",()->sendKeyTap(KeyEvent.KEYCODE_ESCAPE)));
        content.addView(controlAction("CTRL",()->sendKeyTap(KeyEvent.KEYCODE_CTRL_LEFT)));
        content.addView(controlAction("ALT",()->sendKeyTap(KeyEvent.KEYCODE_ALT_LEFT)));
        LinearLayout arrows=new LinearLayout(this);
        for(int key:new int[]{KeyEvent.KEYCODE_DPAD_LEFT,KeyEvent.KEYCODE_DPAD_UP,
                KeyEvent.KEYCODE_DPAD_DOWN,KeyEvent.KEYCODE_DPAD_RIGHT}) {
            final int eventKey=key;
            final String text=key==KeyEvent.KEYCODE_DPAD_LEFT?"◀":
                    key==KeyEvent.KEYCODE_DPAD_UP?"▲":
                    key==KeyEvent.KEYCODE_DPAD_DOWN?"▼":"▶";
            arrows.addView(controlAction(text,()->sendKeyTap(eventKey)),
                    new LinearLayout.LayoutParams(0,dp(48),1));
        }
        content.addView(arrows);
        content.addView(controlAction("HOME / END / PGUP / PGDN",()->
                new AlertDialog.Builder(this)
                    .setItems(new String[]{"HOME","END","PGUP","PGDN"},(d,index)->
                        sendKeyTap(new int[]{KeyEvent.KEYCODE_MOVE_HOME,
                                KeyEvent.KEYCODE_MOVE_END,KeyEvent.KEYCODE_PAGE_UP,
                                KeyEvent.KEYCODE_PAGE_DOWN}[index])).show()));
        content.addView(controlAction("الشاشة والأداء",this::showDisplayInformation));
        content.addView(controlAction("التشخيص والسجلات",this::openDiagnostics));
        content.addView(controlAction("مدير ملفات RM11",this::finish));
        ScrollView scroll=new ScrollView(this);
        scroll.addView(content);
        int screenHeight=getResources().getDisplayMetrics().heightPixels;
        controlPopup=new PopupWindow(scroll,dp(265),
                Math.min(dp(530),Math.max(dp(210),screenHeight-dp(70))),true);
        controlPopup.setBackgroundDrawable(
                new android.graphics.drawable.ColorDrawable(0xff142238));
        controlPopup.setOutsideTouchable(true);
        controlPopup.setElevation(dp(8));
        controlPopup.showAtLocation(getLorieView(),Gravity.CENTER,0,0);
    }

    private void sendKeyTap(int code) {
        if(getLorieView()==null || !getLorieView().connected())return;
        long ms=SystemClock.uptimeMillis();
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_DOWN,code,0));
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_UP,code,0));
        getLorieView().requestFocus();
    }

    private void sendWinefileFullScreenShortcut() {
        // Winefile's own upstream Options > Full Screen shortcut is Ctrl+Shift+S.
        // Unlike X11 window hacks, it is owned by Winefile and is reversible.
        if(getLorieView()==null || !getLorieView().connected())return;
        long t=SystemClock.uptimeMillis();
        int[] down={KeyEvent.KEYCODE_CTRL_LEFT,KeyEvent.KEYCODE_SHIFT_LEFT,
                KeyEvent.KEYCODE_S};
        for(int key:down)handleKey(new KeyEvent(t,t,KeyEvent.ACTION_DOWN,key,0));
        for(int i=down.length-1;i>=0;--i)
            handleKey(new KeyEvent(t,t,KeyEvent.ACTION_UP,down[i],0));
        OfflineDiagnosticJournal.record(this,"v414-winefile-fullscreen",
                "RM11_V414_WINEFILE_FULLSCREEN_SHORTCUT_SENT_NOT_VISUALLY_VERIFIED");
        getLorieView().requestFocus();
    }

    private void showDisplayInformation() {
        float hz=getWindowManager().getDefaultDisplay().getRefreshRate();
        String details="Android: "+getResources().getDisplayMetrics().widthPixels
                +"x"+getResources().getDisplayMetrics().heightPixels
                +"\nمعدل التحديث: "+hz+" Hz (ليس عدد فريمات الألعاب)"
                +"\nتكبير الدقة المنطقية: 150% + عرض ممتد"
                +"\n"+lastViewportEvidence
                +"\n"+lastPhoneDriveEvidence
                +"\nلوحة الاختصارات مرئية: "+keysPanelVisible;
        new AlertDialog.Builder(this).setTitle("الشاشة والأداء")
                .setMessage(details).setPositiveButton("تم",null).show();
    }

    @Override public void onBackPressed() {
        showBackControls();
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
        // Match the actual X11 logical root rather than the physical Surface:
        // the native Lorie 125% scaling intentionally changes resolution.
        int desktopW=w, desktopH=h;
        String rootInfo=NativeDesktopVisualEvidence.auditX11();
        java.util.regex.Matcher logical=java.util.regex.Pattern
                .compile("x11_root_pixels=(\\d+)x(\\d+)").matcher(rootInfo);
        if(logical.find()) {
            try {
                int rw=Integer.parseInt(logical.group(1));
                int rh=Integer.parseInt(logical.group(2));
                if(rw>=320&&rw<=8192&&rh>=240&&rh<=8192) {
                    desktopW=rw;desktopH=rh;
                }
            } catch(NumberFormatException ignored){}
        } else if(prefs!=null && "scaled".equals(prefs.displayResolutionMode.get())) {
            int scale=prefs.displayScale.get();
            if(scale>=100&&scale<=250) {
                desktopW=Math.max(320,((w*100/scale)/8)*8);
                desktopH=Math.max(240,h*100/scale);
            }
        }
        lastViewportEvidence="RM11_V414_ANDROID_SURFACE_PIXELS="+w+"x"+h
                +"\nRM11_V414_WINE_DESKTOP_X11_LOGICAL="+desktopW+"x"+desktopH
                +"\n"+rootInfo;
        OfflineDiagnosticJournal.record(this,"v414-display-geometry",lastViewportEvidence);
        OfflineDiagnosticJournal.record(this,"v4-native-x11-connect",
                "RM11_V4_NATIVE_X11_HANDSHAKE_ACCEPTED\n"
                +(relay==null?"RELAY_MISSING":relay.diagnostics())
                +"RM11_V4_DISPLAY_GLYPHS_NOT_YET_VERIFIED\n");
        WineAutoDesktopRunner.Session current=new WineAutoDesktopRunner.Session();
        session=current;
        lastStatus="X.Org متصل؛ جاري تشغيل Wine...";
        finalReport=WineAutoDesktopRunner.run(this,current,
                value->{
                    lastStatus=value;
                    if(!winefileMaximizeScheduled &&
                            (value.contains("واجهة Wine تعمل") ||
                             value.contains("يجري فحص خطوط مدير الملفات"))) {
                        winefileMaximizeScheduled=true;
                        ui.postDelayed(()->{
                            if(!shuttingDown && !isFinishing())
                                sendWinefileFullScreenShortcut();
                        },4000);
                    }
                    if(value.startsWith("خادم Wine يعمل لكن مدير الملفات خرج.")) {
                        runOnUiThread(()->showWineFailureOverlay(
                                "مدير ملفات Windows توقف، وخادم Wine لا يزال يعمل."));
                    }
                },desktopW,desktopH);
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
                +"RM11 v4.0.14 fullscreen geometry:\n"+lastViewportEvidence+"\n"
                +lastPhoneDriveEvidence+"\n"
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
        shuttingDown=true;
        ui.removeCallbacks(nativeReadiness);
        if(controlPopup!=null)controlPopup.dismiss();
        if(Build.VERSION.SDK_INT>=33 && backControlsCallback!=null)
            getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(backControlsCallback);

        if(session!=null)session.close();
        if(relay!=null)relay.close();
        if(nativeServiceBound)unbindService(this);
        if(nativeServiceRequested)stopService(new Intent(this,RM11NativeX11Service.class));
        wineWorker.shutdownNow();
        exportWorker.shutdown();
        super.onDestroy();
    }
}
