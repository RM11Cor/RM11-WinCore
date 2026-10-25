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
    private final ExecutorService frameFitWorker=Executors.newSingleThreadExecutor();
    private NativeX11TcpBridge relay;
    private WineAutoDesktopRunner.Session session;
    private String finalReport="";
    private volatile String lastStatus="جاري بدء خادم X.Org الأصلي...";
    private volatile String lastVisualEvidence="RM11_V410_FRAME_EVIDENCE_NOT_CAPTURED";
    private volatile String lastViewportEvidence="RM11_V416_SCREEN_NOT_MEASURED";
    private volatile String lastFrameFitEvidence="RM11_V418_FRAME_NOT_MEASURED";
    private volatile String lastPhoneDriveEvidence="RM11_V414_PHONE_DRIVE_NOT_CHECKED";
    private boolean keysPanelVisible;
    private volatile boolean winefileMaximizeScheduled;
    private PopupWindow controlPopup;
    private OnBackInvokedCallback backControlsCallback;
    private boolean shuttingDown;
    private boolean wineStarted;
    private volatile boolean wineGuiProcessStarted;
    private RM11DesktopStartupOverlay startupCurtain;
    private long startupCurtainBegan;
    private int startupWhiteFrames;
    private boolean nativeServiceRequested;
    private boolean nativeServiceBound;
    private boolean binderEverConnected;
    private volatile IBinder nativeServerBinder;
    private int binderAttempts;
    private final Runnable nativeReadiness=new Runnable() {
        private int attempts;
        private int landscapeStableFrames;
        @Override public void run() {
            if(shuttingDown || isFinishing() || wineStarted)return;
            connectNativeSurfaceIfReady();
            if(getLorieView()!=null && getLorieView().connected()
                    && getLorieView().getWidth()>getLorieView().getHeight()
                    && getLorieView().getHeight()>240
                    && ++landscapeStableFrames>=3) {
                wineStarted=true;
                final int w=getLorieView().getWidth();
                final int h=getLorieView().getHeight();
                wineWorker.execute(()->launchWhenX11Ready(w,h));
                // Audit actual X11 windows and displayed Android pixels automatically.
                ui.postDelayed(thisActivityVisualAudit(),6000);
                ui.postDelayed(thisActivityVisualAudit(),14000);
                return;
            }
            if(getLorieView()==null || getLorieView().getWidth()<=getLorieView().getHeight())
                landscapeStableFrames=0;
            if(++attempts<80)ui.postDelayed(this,350);
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
            // Device evidence: native X11 root 1792x810 was rendered into
            // Android display 2688x1216, leaving large black side/bottom.
            // 100% fixes guest/surface dimension mismatch; Wine DPI handles
            // readability independently, without reducing the X11 viewport.
            prefs.putInt("displayScale",100);
            prefs.displayStretch.put(true);
        }
        applyRm11ImmersiveScreen();
        if(getLorieView()!=null) getLorieView().triggerCallback();
        enlargeX11DisconnectedMenu();
        installBackOnlyControls();
        installNativeStartupCurtain();
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

    /**
     * IntroActivity fades after 1550 ms; X11 usually needs longer.
     * Keep animated RM11 graphics over the blank Surface until real UI
     * pixels appear in at least two consecutive PixelCopy measurements.
     */
    private void installNativeStartupCurtain() {
        startupCurtain=new RM11DesktopStartupOverlay(this);
        startupCurtainBegan=SystemClock.elapsedRealtime();
        addContentView(startupCurtain,new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        startupCurtain.bringToFront();
        ui.postDelayed(startupCurtainProbe,850);
        OfflineDiagnosticJournal.record(this,"v419-startup-visual",
                "RM11_V419_NATIVE_BOOT_CURTAIN_INSTALLED");
    }

    private final Runnable startupCurtainProbe=new Runnable() {
        @Override public void run() {
            if(shuttingDown||isFinishing()||startupCurtain==null)return;
            long elapsed=SystemClock.elapsedRealtime()-startupCurtainBegan;
            if(elapsed>52000) {
                startupCurtain.updateStatus(
                        "التشغيل تأخر. اضغط هنا لفتح التشخيص.");
                startupCurtain.setOnClickListener(v->openDiagnostics());
            }
            if(wineGuiProcessStarted && getLorieView()!=null
                    && getLorieView().connected()
                    && getLorieView().getHolder().getSurface().isValid()) {
                NativeDesktopVisualEvidence.auditSurface(getLorieView(),ui,proof->{
                    if(shuttingDown||isFinishing()||startupCurtain==null)return;
                    int dark=readPixelCount(proof,"near_black_pixels=");
                    int opaque=readPixelCount(proof,"opaque_pixels=");
                    boolean whiteGui=dark>=0 && dark<3200 && opaque>2800;
                    startupWhiteFrames=whiteGui?startupWhiteFrames+1:0;
                    if(startupWhiteFrames>=2) {
                        OfflineDiagnosticJournal.record(
                                RM11NativeWineActivity.this,"v419-startup-visual",
                                "RM11_V419_REAL_X11_GUI_VISIBLE_BEFORE_ANIMATION_FADE\n"
                                +proof);
                        RM11DesktopStartupOverlay curtain=startupCurtain;
                        startupCurtain=null;
                        if(curtain!=null)curtain.revealDesktop(null);
                        return;
                    }
                    ui.postDelayed(this,800);
                });
            }else {
                ui.postDelayed(this,800);
            }
        }
    };

    private int readPixelCount(String audit,String marker) {
        int start=audit.indexOf(marker);
        if(start<0)return -1;
        start+=marker.length();
        int stop=start;
        while(stop<audit.length() && Character.isDigit(audit.charAt(stop)))stop++;
        try { return Integer.parseInt(audit.substring(start,stop)); }
        catch(NumberFormatException e){return -1;}
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
        TextView heading=new TextView(this);
        heading.setText("RM11  •  قائمة التحكم");
        heading.setTextColor(Color.WHITE);
        heading.setTextSize(19);
        heading.setGravity(Gravity.CENTER_VERTICAL|Gravity.RIGHT);
        heading.setPadding(dp(8),dp(13),dp(8),dp(18));
        content.addView(heading);
        content.addView(controlAction("⟵  الخروج من سطح مكتب Windows",this::confirmExitToFileLauncher));

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
        content.addView(controlAction("طريقة تحريك الماوس واللمس",()->
                new AlertDialog.Builder(this)
                        .setTitle("طريقة التنقل داخل ملفات Windows")
                        .setSingleChoiceItems(
                                new String[]{"ماوس ولوحة لمس","محاكاة لمس الشاشة","لمس مباشر"},
                                prefs==null?0:Math.max(0,Math.min(2,
                                        Integer.parseInt(prefs.touchMode.get())-1)),
                                (d,index)->{
                                    if(prefs!=null) {
                                        prefs.touchMode.put(String.valueOf(index+1));
                                        if(getLorieView()!=null) {
                                            getLorieView().reloadPreferences(prefs);
                                            getLorieView().triggerCallback();
                                        }
                                    }
                                    OfflineDiagnosticJournal.record(this,"v416-touch-mode",
                                            "RM11_V416_TOUCH_MODE="+(index+1));
                                    d.dismiss();
                                }).setNegativeButton("إلغاء",null).show()));
        content.addView(controlAction("الشاشة والأداء",this::showDisplayInformation));
        content.addView(controlAction("التشخيص والسجلات",this::openDiagnostics));
        ScrollView scroll=new ScrollView(this);
        scroll.addView(content);
        int screenHeight=getResources().getDisplayMetrics().heightPixels;
        // Emulator-style side drawer, not a centered Android popup.
        // Full-height right rail overlays the X11 surface only while Back
        // menu is open; never shrinks the native desktop viewport.
        int railWidth=Math.min(dp(330),
                Math.max(dp(230),getResources().getDisplayMetrics().widthPixels*36/100));
        controlPopup=new PopupWindow(scroll,railWidth,
                ViewGroup.LayoutParams.MATCH_PARENT,true);
        controlPopup.setEnterTransition(new android.transition.Slide(Gravity.RIGHT));
        controlPopup.setExitTransition(new android.transition.Slide(Gravity.RIGHT));
        controlPopup.setBackgroundDrawable(
                new android.graphics.drawable.ColorDrawable(0xff142238));
        controlPopup.setOutsideTouchable(true);
        controlPopup.setElevation(dp(8));
        controlPopup.showAtLocation(getLorieView(),Gravity.RIGHT|Gravity.TOP,0,0);
        OfflineDiagnosticJournal.record(this,"v416-side-drawer",
                "RM11_V416_MENU_SIDE=RIGHT\nRM11_V416_DRAWER_FULL_HEIGHT="+screenHeight);
    }

    private void confirmExitToFileLauncher() {
        // Leaving the desktop is a lifecycle action, not a Windows hotkey.
        // Warn once so a future game cannot lose unsaved work by accidental tap.
        new AlertDialog.Builder(this)
                .setTitle("الخروج من سطح مكتب Windows")
                .setMessage("ترجع الآن إلى قائمة ملفات RM11. برامج Windows المفتوحة راح تنغلق، لكن ملفات C: وD: وملفات الهاتف تبقى بمكانها.")
                .setNegativeButton("إلغاء",null)
                .setPositiveButton("خروج إلى ملفات RM11",(dialog,which)->exitToFileLauncher())
                .show();
    }

    private void exitToFileLauncher() {
        if(shuttingDown || isFinishing())return;
        OfflineDiagnosticJournal.record(this,"v417-desktop-exit",
                "RM11_V417_USER_REQUESTED_DESKTOP_EXIT\n"
                +"RM11_V417_DESTINATION_NATIVE_FILES_LAUNCHER\n"
                +"RM11_V417_NO_USER_FILE_DELETE");
        // Return to the existing host Activity rather than creating another
        // Windows desktop. finish() calls onDestroy(), which closes session,
        // TCP relay and the X.Org service owned by this Activity.
        Intent launcher=new Intent(this,RM11FileLauncherActivity.class);
        launcher.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP|Intent.FLAG_ACTIVITY_SINGLE_TOP);
        startActivity(launcher);
        finish();
        overridePendingTransition(android.R.anim.fade_in,android.R.anim.fade_out);
    }

    private void sendKeyTap(int code) {
        if(getLorieView()==null || !getLorieView().connected())return;
        long ms=SystemClock.uptimeMillis();
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_DOWN,code,0));
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_UP,code,0));
        getLorieView().requestFocus();
    }

    private void requestWinefileMaximized() {
        // Win32 system-menu Maximize is idempotent. A blind Ctrl+Shift+S
        // would *toggle* Winefile fullscreen OFF if a previous session
        // restored the fullscreen setting from the prefix.
        if(shuttingDown || isFinishing() || getLorieView()==null
                || !getLorieView().connected())return;
        getLorieView().requestFocus();
        sendAltWindowMenu(KeyEvent.KEYCODE_SPACE);
        OfflineDiagnosticJournal.record(this,"v415-winefile-frame",
                "RM11_V415_MAIN_FRAME_MAXIMIZE_SYSTEM_MENU_SENT_UNVERIFIED");
        ui.postDelayed(this::maximizeWinefileMdiChild,850);
    }

    private void sendAltWindowMenu(int menuKey) {
        long ms=SystemClock.uptimeMillis();
        int alt=KeyEvent.META_ALT_ON | KeyEvent.META_ALT_LEFT_ON;
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_DOWN,KeyEvent.KEYCODE_ALT_LEFT,0,alt));
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_DOWN,menuKey,0,alt));
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_UP,menuKey,0,alt));
        handleKey(new KeyEvent(ms,ms,KeyEvent.ACTION_UP,KeyEvent.KEYCODE_ALT_LEFT,0,0));
        ui.postDelayed(()->{
            if(!shuttingDown&&!isFinishing())sendKeyTap(KeyEvent.KEYCODE_X);
        },220);
    }

    private void maximizeWinefileMdiChild() {
        // Winefile is a Win32 multiple-document window: the nested white
        // file panel must be maximized *separately* from the gray frame.
        // Alt+Minus invokes the active MDI child's system menu and X
        // selects Maximize, not a reversible fullscreen toggle.
        if(shuttingDown||isFinishing()||getLorieView()==null
                ||!getLorieView().connected())return;
        sendAltWindowMenu(KeyEvent.KEYCODE_MINUS);
        OfflineDiagnosticJournal.record(this,"v415-winefile-mdi",
                "RM11_V415_MDI_CHILD_MAXIMIZE_MENU_SEQUENCE_SENT_UNVERIFIED");
    }

    private void fitWinefileNativeX11Frame() {
        if(shuttingDown || isFinishing())return;
        frameFitWorker.execute(()->{
            String outcome=NativeDesktopVisualEvidence.fitSingleVisibleTopLevelWindow();
            lastFrameFitEvidence=outcome;
            OfflineDiagnosticJournal.record(this,"v418-x11-frame-size",outcome);
        });
    }

    private void showDisplayInformation() {
        float hz=getWindowManager().getDefaultDisplay().getRefreshRate();
        String details="Android: "+getResources().getDisplayMetrics().widthPixels
                +"x"+getResources().getDisplayMetrics().heightPixels
                +"\nمعدل التحديث: "+hz+" Hz (ليس عدد فريمات الألعاب)"
                +"\nالدقة: 100% أصلية للشاشة؛ تكبير خطوط Wine DPI=144"
                +"\n"+lastViewportEvidence+"\n"+lastFrameFitEvidence
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
        // Native Lorie view can initially report a *portrait* viewport on
        // a device that immediately rotates to landscape. v4.0.15 device
        // journal: first guest root 808x1792; actual later 1792x810 with
        // Android physical pixels 2688x1216. Never spawn Explorer for the
        // stale portrait root. Wait for the native X11 mode to settle.
        String orientationTrace="";
        String settledRoot="";
        int probeW=0, probeH=0,stableRoot=0;
        for(int tries=0;tries<28 && !shuttingDown && !Thread.currentThread().isInterrupted();tries++) {
            String root=NativeDesktopVisualEvidence.auditX11();
            java.util.regex.Matcher rootMatch=java.util.regex.Pattern
                    .compile("x11_root_pixels=(\\d+)x(\\d+)").matcher(root);
            if(rootMatch.find()) {
                try {
                    int rw=Integer.parseInt(rootMatch.group(1));
                    int rh=Integer.parseInt(rootMatch.group(2));
                    if(rw>rh && rw>=w-32 && rw<=w+32 &&
                            rh>=h-32 && rh<=h+32 &&
                            rw==probeW && rh==probeH)stableRoot++;
                    else stableRoot=0;
                    probeW=rw; probeH=rh;
                    orientationTrace="x11="+rw+"x"+rh+" android="+w+"x"+h
                            +" stable="+stableRoot+" samples="+(tries+1);
                    if(stableRoot>=2) {
                        settledRoot=root;
                        break;
                    }
                }catch(NumberFormatException ignored){}
            }
            try { Thread.sleep(230); }
            catch(InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        if(settledRoot.isEmpty()) {
            lastStatus="RM11_V416_LANDSCAPE_X11_ROOT_NOT_STABLE";
            OfflineDiagnosticJournal.record(this,"v416-screen-fit",
                    lastStatus+"\n"+orientationTrace);
            runOnUiThread(()->showConnectionStatus(
                    "سطح Windows بعده غير متطابق مع حجم الشاشة، راجع التشخيص."));
            return;
        }
        OfflineDiagnosticJournal.record(this,"v416-screen-fit",
                "RM11_V416_X11_MATCHES_PHYSICAL_LANDSCAPE\n"+orientationTrace+
                "\nRM11_V416_NO_PORTRAIT_DESKTOP_LAUNCH");
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
                    if(value.contains("واجهة Wine تعمل") ||
                            value.contains("يجري فحص خطوط مدير الملفات"))
                        wineGuiProcessStarted=true;
                    if(!winefileMaximizeScheduled &&
                            (value.contains("واجهة Wine تعمل") ||
                             value.contains("يجري فحص خطوط مدير الملفات"))) {
                        winefileMaximizeScheduled=true;
                        ui.postDelayed(()->{
                            if(!shuttingDown && !isFinishing())
                                requestWinefileMaximized();
                            // Win32 keyboard menu can miss the main frame if
                            // focus belongs to the nested Winefile MDI child.
                            // Independently ask X11 to measure/resize the one
                            // mapped Winefile frame; never resize arbitrary
                            // game windows when several are visible.
                            ui.postDelayed(this::fitWinefileNativeX11Frame,1500);
                            ui.postDelayed(this::fitWinefileNativeX11Frame,4900);
                        },6500);
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
                +"RM11 v4.0.14 fullscreen geometry:\n"+lastViewportEvidence+"\n"                +"RM11 v4.0.18 actual Winefile X11 frame:\n"+lastFrameFitEvidence+"\n"
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
        ui.removeCallbacks(startupCurtainProbe);
        if(startupCurtain!=null){
            startupCurtain.stop();
            startupCurtain=null;
        }
        if(controlPopup!=null)controlPopup.dismiss();
        if(Build.VERSION.SDK_INT>=33 && backControlsCallback!=null)
            getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(backControlsCallback);

        if(session!=null)session.close();
        if(relay!=null)relay.close();
        if(nativeServiceBound)unbindService(this);
        if(nativeServiceRequested)stopService(new Intent(this,RM11NativeX11Service.class));
        wineWorker.shutdownNow();
        frameFitWorker.shutdownNow();
        exportWorker.shutdown();
        super.onDestroy();
    }
}
