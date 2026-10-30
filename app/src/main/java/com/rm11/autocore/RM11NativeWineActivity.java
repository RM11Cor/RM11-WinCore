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
import android.view.MotionEvent;
import android.view.InputDevice;
import android.hardware.input.InputManager;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
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
import com.rm11.autocore.runtime.NovaWineExeLauncher;
import com.rm11.autocore.runtime.NovaExeWindowEvidence;
import com.rm11.autocore.runtime.FontSandboxEvidence;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import com.termux.x11.MainActivity;
import com.termux.x11.RM11NativeX11Service;
import com.termux.x11.RM11NativeDisplayConnector;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * v4 PREVIEW: real X.Org LorieView surface, not legacy Java ScreenView.
 * Start X.Org in a dedicated Android service process and relay the unchanged
 * Wine DISPLAY TCP port to its private AF_UNIX X socket.
 *
 * This version remains a device preview: a successful CI APK build is not
 * proof of readable glyphs or a working Wine desktop on REDMAGIC.
 */
public final class RM11NativeWineActivity extends MainActivity implements ServiceConnection {
    public static final String EXTRA_DIRECT_GAME_EXE="com.rm11.autocore.DIRECT_GAME_EXE";
    public static final String EXTRA_SEH_PROBE="com.rm11.autocore.SEH_NATIVE_PROBE";
    public static final String EXTRA_FIBER_SEH_PROBE="com.rm11.autocore.FIBER_SEH_PROBE";
    public static final String EXTRA_V474_X11_SURFACE_TEST="com.rm11.autocore.V474_X11_SURFACE_TEST";
    private boolean directGameMode;
    private boolean sehProbeMode;
    private boolean fiberSehProbeMode;
    private boolean x11SurfaceTestMode;
    private Path requestedGame;
    private static final int EXPORT_DIAGNOSTICS=9400;
    private static final int SEPARATE_FONT_SANDBOX=9405;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService wineWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService exportWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService frameFitWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService exeWorker=Executors.newSingleThreadExecutor();
    private final ExecutorService exeProbeWorker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean exeLaunchBusy=new AtomicBoolean(false);
    private volatile Process selectedExeProcess;
    private NativeX11TcpBridge relay;
    private WineAutoDesktopRunner.Session session;
    private String finalReport="";
    private volatile String lastStatus="جاري بدء خادم X.Org الأصلي...";
    private volatile String lastVisualEvidence="RM11_V410_FRAME_EVIDENCE_NOT_CAPTURED";
    private volatile String lastViewportEvidence="RM11_V416_SCREEN_NOT_MEASURED";
    private volatile String lastFrameFitEvidence="RM11_V418_FRAME_NOT_MEASURED";
    private volatile String lastPhoneDriveEvidence="RM11_V414_PHONE_DRIVE_NOT_CHECKED";
    private volatile String lastFontSandboxEvidence="RM11_V445_SEPARATE_PROCESS_NOT_YET_TESTED";
    private boolean keysPanelVisible;
    private volatile boolean winefileMaximizeScheduled;
    private PopupWindow controlPopup;
    // v49035: CarX-only held-key multi-touch overlay. No changes to Wine,
    // Vulkan, FEX, DXVK or the underlying Lorie input pipeline.
    private RM11CarXTouchControls gameTouchControls;
    private RM11VirtualXInputV49037 xinputState;
    private RM11VirtualGamepadOverlayV49037 xinputOverlay;
    private RM11UniversalPadV49039 universalPad;
    private final android.util.SparseLongArray touchKeyDownTimes=
            new android.util.SparseLongArray();
    private final java.util.Set<Integer> touchKeysReported=
            new java.util.HashSet<>();
    private final java.util.Set<Integer> touchSourceHeld=
            new java.util.HashSet<>();
    private final java.util.Set<Integer> gamepadSourceHeld=
            new java.util.HashSet<>();
    private RM11GamepadDriveV49036 gamepadDrive;
    private InputManager gamepadInputManager;
    private int lastGamepadDeviceId=-1;
    private boolean physicalPadConnected;
    private boolean gamepadFirstLogged;
    private int inputTraceCount;
    private int keyboardForwardedDown;
    private int keyboardForwardedUp;
    private final InputManager.InputDeviceListener gamepadDisconnectListener=
            new InputManager.InputDeviceListener() {
                @Override public void onInputDeviceAdded(int id){
                    refreshPhysicalGamepadPresence("DEVICE_ADDED");
                }
                @Override public void onInputDeviceChanged(int id){
                    refreshPhysicalGamepadPresence("DEVICE_CHANGED");
                }
                @Override public void onInputDeviceRemoved(int id){
                    if(id==lastGamepadDeviceId){
                        if(xinputState!=null)xinputState.physicalDisconnect();
                        if(gamepadDrive!=null)gamepadDrive.releaseAll();
                        lastGamepadDeviceId=-1;
                    }
                    refreshPhysicalGamepadPresence("DEVICE_REMOVED");
                }
            };
    private OnBackInvokedCallback backControlsCallback;
    private boolean shuttingDown;
    private boolean wineStarted;
    private volatile boolean wineGuiProcessStarted;
    private boolean firstDesktopTouchCaptured;
    // v480: do not forward diagnostic-only touches to X11 and accidentally
    // invalidate a single-frame WSI presentation.
    private boolean firstProbeTouchCaptured;
    private boolean firstGameTouchCaptured;
    private int consecutiveBlackTapFrames;
    private boolean blackScreenReported;
    private View gameNoWindowNotice;
    private RM11DesktopStartupOverlay startupCurtain;
    private NovaDesktopSurface novaDesktop;
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
        getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(0xff07101c));
        if(isFinishing())return;
        // This dedicated diagnostics-only launch starts X.Org and the Lorie
        // Surface, but NEVER starts Wine or any user Windows executable.
        x11SurfaceTestMode=getIntent()!=null
            &&getIntent().getBooleanExtra(EXTRA_V474_X11_SURFACE_TEST,false);
        // A file selection is explicit; never enter the legacy Wine desktop
        // from RM11's game-first native home screen.
        String requested=getIntent()==null?null:
                getIntent().getStringExtra(EXTRA_DIRECT_GAME_EXE);
        fiberSehProbeMode=getIntent()!=null
                &&getIntent().getBooleanExtra(EXTRA_FIBER_SEH_PROBE,false);
        sehProbeMode=fiberSehProbeMode || (getIntent()!=null
                &&getIntent().getBooleanExtra(EXTRA_SEH_PROBE,false));
        if(sehProbeMode) {
            directGameMode=true;
            OfflineDiagnosticJournal.record(this,"v460-seh-request",
                    "RM11_V460_SIGNED_X64_EXCEPTION_PROBE_REQUESTED=true");
        }
        if(requested!=null && !sehProbeMode) {
            directGameMode=true;
            try {
                RuntimeLayout layout=new RuntimeLayout(getFilesDir().toPath(),
                        new File(getApplicationInfo().nativeLibraryDir).toPath());
                requestedGame=NovaWineExeLauncher.validate(layout,Path.of(requested),
                        PhoneDriveBridge.authorized()).path;
                OfflineDiagnosticJournal.record(this,"v455-game-ui",
                        "RM11_V455_DIRECT_GAME_MODE=true\n"
                        +"RM11_V455_SELECTED_EXE="+requestedGame);
            }catch(Exception badSelection) {
                OfflineDiagnosticJournal.record(this,"v455-game-invalid",
                        "RM11_V455_GAME_REJECTED="+badSelection.getMessage());
                Toast.makeText(this,"ملف اللعبة غير صالح: "+badSelection.getMessage(),
                        Toast.LENGTH_LONG).show();
                finish();
                return;
            }
        }
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
        installUniversalGamepad();
        resetLegacyBackSignal();
        // Real Wine X11 framebuffer is the desktop. The old native Nova
        // imitation surface and Winefile-based splash must never cover it.
        OfflineDiagnosticJournal.record(this,"v451-wine-shell",
                "RM11_V451_FAKE_NOVA_OVERLAY_DISABLED=true\n"
                +"RM11_V451_AUTO_WINEFILE_DISABLED=true\n"
                +"RM11_V451_REAL_X11_SURFACE_FOREGROUND=true");
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
        ui.postDelayed(startupCurtainProbe,160);
        OfflineDiagnosticJournal.record(this,"v420-intro-direct",
                "RM11_V420_INTRO_PERSISTENT_SINGLE_ACTIVITY_WITHOUT_TIMER");
        OfflineDiagnosticJournal.record(this,"v419-startup-visual",
                "RM11_V419_NATIVE_BOOT_CURTAIN_INSTALLED");
    }

    private final Runnable startupCurtainProbe=new Runnable() {
        @Override public void run() {
            if(shuttingDown||isFinishing()||startupCurtain==null)return;
            long elapsed=SystemClock.elapsedRealtime()-startupCurtainBegan;
            if(elapsed>52000) {
                startupCurtain.updateStatus("Windows ما اكتمل رسمه؛ اضغط لفتح التشخيص.");
                startupCurtain.setOnClickListener(v->openDiagnostics());
            } else if(elapsed>21000) {
                startupCurtain.updateStatus(
                        "جاري تجهيز الملفات... اضغط هنا لعرض سطح المكتب مباشرة.");
                startupCurtain.setOnClickListener(v->{
                    OfflineDiagnosticJournal.record(RM11NativeWineActivity.this,
                            "v420-startup-manual",
                            "RM11_V420_USER_REQUESTED_EARLY_REVEAL");
                    RM11DesktopStartupOverlay curtain=startupCurtain;
                    startupCurtain=null;
                    if(curtain!=null)curtain.revealDesktop(null);
                });
            }
            if(wineGuiProcessStarted && getLorieView()!=null
                    && getLorieView().connected()
                    && getLorieView().getHolder().getSurface().isValid()) {
                NativeDesktopVisualEvidence.auditWinefileReady(getLorieView(),ui,proof->{
                    if(shuttingDown||isFinishing()||startupCurtain==null)return;
                    boolean realGui=proof.contains("RM11_V420_GUI_READY=true");
                    startupWhiteFrames=realGui?startupWhiteFrames+1:0;
                    if(startupWhiteFrames>=2) {
                        OfflineDiagnosticJournal.record(
                                RM11NativeWineActivity.this,"v419-startup-visual",
                                "RM11_V421_FILE_LIST_UI_VERIFIED_2_FRAMES_BEFORE_FADE\n"
                                +proof
                                +"\nRM11_V425_BOOT_TO_VERIFIED_GUI_MS="+
                                (SystemClock.elapsedRealtime()-startupCurtainBegan));
                        RM11DesktopStartupOverlay curtain=startupCurtain;
                        startupCurtain=null;
                        if(curtain!=null)curtain.revealDesktop(null);
                        return;
                    }
                    ui.postDelayed(this,180);
                });
            }else {
                ui.postDelayed(this,180);
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
        if(focused){
            applyRm11ImmersiveScreen();
            if(universalPad!=null)refreshPhysicalGamepadPresence("WINDOW_FOCUS");
        }else releaseAllCarXKeys();
    }

    /** Old helper may see a persisted back signal from prior versions.
     * Reset the private control marker without displaying any Android overlay. */
    private void resetLegacyBackSignal() {
        try {
            java.nio.file.Files.write(new File(getFilesDir(),
                    "rm11-winefile-nav-v421.signal").toPath(),new byte[]{'0','\n'});
        }catch(IOException failure) {
            OfflineDiagnosticJournal.record(this,"v425-navigation",
                    "RM11_V425_OLD_NAV_SIGNAL_RESET_FAILED");
        }
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


    /** Drawer only: never treat an Android Back/swipe as a request to type.
     * The in-game keyboard remains available from its explicit menu action. */
    private void hideImeForControlsDrawer() {
        // This is triggered only by opening the side drawer; do not change
        // the X11 Surface, Wine focus geometry, or input mode preferences.
        if(getLorieView()!=null)getLorieView().setKeyboardVisible(false);
        InputMethodManager imm=(InputMethodManager)
                getSystemService(Context.INPUT_METHOD_SERVICE);
        if(imm!=null) {
            if(getLorieView()!=null && getLorieView().getWindowToken()!=null)
                imm.hideSoftInputFromWindow(getLorieView().getWindowToken(),0);
            View decor=getWindow().getDecorView();
            if(decor!=null && decor.getWindowToken()!=null)
                imm.hideSoftInputFromWindow(decor.getWindowToken(),0);
        }
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
        content.addView(controlAction("▣  شاشة Wine الحقيقية",()->{
            if(getLorieView()!=null)getLorieView().requestFocus();
        }));
        content.addView(controlAction(directGameMode
                ?"⟵  إغلاق اللعبة والعودة لمدير الملفات"
                :"⟵  الخروج من سطح مكتب Windows",this::confirmExitToFileLauncher));

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
        // Buttons remain clickable by touch; the drawer is NOT an editor.
        // Avoid transferring input-method focus away from Lorie/X11.
        scroll.setFocusable(false);
        scroll.setFocusableInTouchMode(false);
        content.setFocusable(false);
        content.setFocusableInTouchMode(false);
        scroll.addView(content);
        int screenHeight=getResources().getDisplayMetrics().heightPixels;
        // Emulator-style side drawer, not a centered Android popup.
        // Full-height right rail overlays the X11 surface only while Back
        // menu is open; never shrinks the native desktop viewport.
        int railWidth=Math.min(dp(330),
                Math.max(dp(230),getResources().getDisplayMetrics().widthPixels*36/100));
        // v426: focusable=true stole Lorie's IME focus when the drawer slid
        // in, even though INPUT_METHOD_NOT_NEEDED was already configured.
        // A non-focusable popup still receives button touch/clicks.
        controlPopup=new PopupWindow(scroll,railWidth,
                ViewGroup.LayoutParams.MATCH_PARENT,false);
        controlPopup.setFocusable(false);
        controlPopup.setTouchable(true);
        controlPopup.setEnterTransition(new android.transition.Slide(Gravity.RIGHT));
        controlPopup.setExitTransition(new android.transition.Slide(Gravity.RIGHT));
        controlPopup.setBackgroundDrawable(
                new android.graphics.drawable.ColorDrawable(0xff142238));
        // PopupWindow does not need keyboard input; prevent IME flash.
        controlPopup.setInputMethodMode(PopupWindow.INPUT_METHOD_NOT_NEEDED);
        controlPopup.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN
                | WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING);
        controlPopup.setOutsideTouchable(true);
        controlPopup.setElevation(dp(8));
        hideImeForControlsDrawer();
        controlPopup.showAtLocation(getLorieView(),Gravity.RIGHT|Gravity.TOP,0,0);
        // A focused IME may report an asynchronous visibility event after
        // the popup animation begins; suppress it only while drawer is open.
        ui.postDelayed(()->{
            if(controlPopup!=null && controlPopup.isShowing())
                hideImeForControlsDrawer();
        },120);
        OfflineDiagnosticJournal.record(this,"v416-side-drawer",
                "RM11_V416_MENU_SIDE=RIGHT\nRM11_V416_DRAWER_FULL_HEIGHT="+screenHeight
                +"\nRM11_V426_DRAWER_NONFOCUSABLE_IME_HIDDEN_MANUAL_ONLY");
    }

    /**
     * Explicitly selected desktop/Explorer EXE. Reuse current Wine prefix,
     * wineserver and X11 endpoint, never restart or reset the runtime.
     * A native ProcessBuilder spawn is NOT proof of game compatibility.
     */
    /**
     * The EXE loader is a single-flight operation. A second tap while the
     * first command is still starting must not queue a surprise later launch.
     * X11 snapshots show window-count observations, not window ownership.
     */
    private void launchSelectedExe(File exe,boolean fontRepair){
        if(shuttingDown||isFinishing())return;
        if(!wineStarted||!wineGuiProcessStarted||session==null||
                !session.canLaunchExe()||
                getLorieView()==null||!getLorieView().connected()){
            new AlertDialog.Builder(this).setTitle("محرك Windows")
                .setMessage("جلسة Wine غير مستقرة أو مدير ملفات Windows لم يجهز. "+
                    "إذا توقف wineserver، افتح جلسة جديدة أولاً. التفاصيل في التشخيص.")
                .setPositiveButton("Diagnostics",(d,w)->openDiagnostics())
                .setNegativeButton("Cancel",null).show();
            OfflineDiagnosticJournal.record(this,"v436-exe-guard",
                    "RM11_V436_EXE_DEFERRED_WINE_OR_X11_NOT_READY");
            return;
        }
        if(!exeLaunchBusy.compareAndSet(false,true)){
            Toast.makeText(this,"محاولة تشغيل EXE جارية. لا يمكن بدء تشغيل ثانٍ الآن.",
                    Toast.LENGTH_SHORT).show();
            return;
        }
        Process prev=selectedExeProcess;
        if(prev!=null&&prev.isAlive()){
            exeLaunchBusy.set(false);
            new AlertDialog.Builder(this).setTitle("Windows EXE")
                .setMessage("يوجد برنامج EXE ما زال قيد التنفيذ. افتح نافذة Windows أولاً.")
                .setPositiveButton("Windows",(d,w)->showWindowsUnderNova())
                .setNegativeButton("Cancel",null).show();
            return;
        }
        try{
            exeWorker.execute(()->{
                try{
                    if(session==null || !session.canLaunchExe())
                        throw new IOException("RM11_V441_EXE_BLOCKED_WINE_SESSION_NO_LONGER_STABLE");
                    final String baseline=NativeDesktopVisualEvidence.auditX11();
                    Process process=NovaWineExeLauncher.start(this,exe.toPath(),
                            PhoneDriveBridge.authorized(),fontRepair);
                    selectedExeProcess=process;
                    OfflineDiagnosticJournal.record(this,"v436-exe-observer",
                            "RM11_V436_EXE_MONITOR_STARTED\n"
                            +"RM11_V436_BASELINE_AUDIT="+
                            (baseline.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK")
                                    ?"ROOT_QUERY_OK":"ROOT_QUERY_FAILED")
                            +"\nRM11_V436_NO_WINDOW_ATTRIBUTION=true");
                    ui.post(()->{
                        if(shuttingDown||isFinishing())return;
                        showWindowsUnderNova();
                        Toast.makeText(this,"بدأت محاولة تشغيل: "+exe.getName(),
                                Toast.LENGTH_LONG).show();
                    });
                    exeProbeWorker.execute(()->auditExeWindowTransitions(process,baseline));
                    String report=NovaWineExeLauncher.consumeAndWait(process);
                    OfflineDiagnosticJournal.record(this,"v436-exe-result",
                            report.length()>21000?report.substring(report.length()-21000):report);
                    ui.post(()->{
                        if(!shuttingDown&&!isFinishing())
                            Toast.makeText(this,
                                    "انتهت عملية تشغيل EXE. افحص التشخيص لمعرفة النتيجة.",
                                    Toast.LENGTH_SHORT).show();
                    });
                }catch(Exception failure){
                    String detail=failure.getClass().getSimpleName()+": "+failure.getMessage();
                    OfflineDiagnosticJournal.record(this,"v436-exe-error",
                            "RM11_V436_EXE_PROCESS_LAUNCH_FAILED\n"+detail);
                    ui.post(()->{
                        if(shuttingDown||isFinishing())return;
                        new AlertDialog.Builder(this).setTitle("تعذّر تشغيل EXE")
                            .setMessage(detail+"\nملفات اللعبة وWine ما تغيرت.")
                            .setPositiveButton("Diagnostics",(d,w)->openDiagnostics())
                            .setNegativeButton("Close",null).show();
                    });
                }finally{
                    selectedExeProcess=null;
                    exeLaunchBusy.set(false);
                }
            });
        }catch(java.util.concurrent.RejectedExecutionException stop){
            exeLaunchBusy.set(false);
        }
    }

    /** Capture two passive X11 observations; never resize or inject input. */
    private void auditExeWindowTransitions(Process launcher,String baseline){
        final long[] pauses={1500,4000};
        for(int i=0;i<pauses.length;i++){
            if(shuttingDown||Thread.currentThread().isInterrupted())return;
            try{Thread.sleep(pauses[i]);}
            catch(InterruptedException interrupted){
                Thread.currentThread().interrupt();return;
            }
            if(shuttingDown)return;
            String after=NativeDesktopVisualEvidence.auditX11();
            String evidence=NovaExeWindowEvidence.compare(baseline,after);
            OfflineDiagnosticJournal.record(this,"v436-exe-x11-evidence",
                    "RM11_V436_WINDOW_AUDIT_STAGE="+(i+1)
                    +"\nRM11_V436_LAUNCHER_ALIVE="+launcher.isAlive()
                    +"\n"+evidence);
        }
    }

    private void showWindowsUnderNova(){
        if(novaDesktop!=null)novaDesktop.hideDesktop();
        if(getLorieView()!=null)getLorieView().requestFocus();
        OfflineDiagnosticJournal.record(this,"v433-nova-desktop",
                "RM11_V433_USER_SWITCHED_TO_ORIGINAL_WINE_X11");
    }
    private void showNovaDesktop(){
        if(novaDesktop!=null)novaDesktop.showDesktop();
        else showConnectionStatus("سطح Nova غير متاح؛ راجع التشخيص.");
        OfflineDiagnosticJournal.record(this,"v433-nova-desktop",
                "RM11_V433_USER_SHOWED_NATIVE_DESKTOP");
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
                +"RM11_V49039_DESTINATION_NATIVE_GAME_LIBRARY\n"
                +"RM11_V417_NO_USER_FILE_DELETE");
        // Return to the existing host Activity rather than creating another
        // Windows desktop. finish() calls onDestroy(), which closes session,
        // TCP relay and the X.Org service owned by this Activity.
        Intent launcher=new Intent(this,RM11GameLibraryActivity.class);
        launcher.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP|Intent.FLAG_ACTIVITY_SINGLE_TOP);
        startActivity(launcher);
        finish();
        overridePendingTransition(android.R.anim.fade_in,android.R.anim.fade_out);
    }

    /**
     * For games use LorieView.sendKeyEvent() directly. MainActivity.handleKey()
     * goes through InputEventSender, which may transform printable key DOWN
     * into sendTextEvent and swallow the key UP when preferScancodes is false.
     * That cannot represent a held W/A/S/D movement key. Native Lorie
     * provides proper, paired key press/release on the existing X11 server.
     */
    private void sendCarXHeldKey(int keyCode,boolean down) {
        sendCarXInputFromSource(keyCode,down,false);
    }

    /**
     * Ref-count by source: Android touch + physical controller can both hold W.
     * Key UP reaches the real X11 transport only when *both* have released it.
     */
    private void sendCarXInputFromSource(int keyCode,boolean down,boolean fromGamepad){
        java.util.Set<Integer> source=fromGamepad?gamepadSourceHeld:touchSourceHeld;
        if(keyCode==0)return;
        if(down){
            if(shuttingDown||isFinishing() || getLorieView()==null
                    ||!getLorieView().connected()){
                if(inputTraceCount++<12)
                    OfflineDiagnosticJournal.record(this,"v49040-input-route",
                        "RM11_V49040_REJECTED_KEY="+KeyEvent.keyCodeToString(keyCode)
                        +"\\nRM11_V49040_REASON=LORIE_NOT_CONNECTED_OR_CLOSING"
                        +"\\nRM11_V49040_GAME_ACK=UNVERIFIED");
                return;
            }
            source.add(keyCode);
        }else{
            source.remove(keyCode);
        }
        boolean shouldDown=touchSourceHeld.contains(keyCode)
                ||gamepadSourceHeld.contains(keyCode);
        int previous=touchKeyDownTimes.indexOfKey(keyCode);
        if(shouldDown && previous<0){
            long now=SystemClock.uptimeMillis();
            touchKeyDownTimes.put(keyCode,now);
            boolean accepted=getLorieView().sendKeyEvent(0,keyCode,true);
            if(!accepted)touchKeyDownTimes.delete(keyCode);
            else keyboardForwardedDown++;
            if(inputTraceCount++<12 || !accepted)
                OfflineDiagnosticJournal.record(this,"v49040-input-route",
                    "RM11_V49040_LORIE_KEY_DOWN="+KeyEvent.keyCodeToString(keyCode)
                    +"\\nRM11_V49040_LORIE_NATIVE_DOWN_ACCEPTED="+accepted
                    +"\\nRM11_V49040_DOWN_COUNT="+keyboardForwardedDown
                    +"\\nRM11_V49040_SOURCE="+(fromGamepad?"PHYSICAL":"TOUCH")
                    +"\\nRM11_V49040_GAME_ACK=UNVERIFIED");
            if(touchKeysReported.add(keyCode)){
                OfflineDiagnosticJournal.record(this,fromGamepad
                        ?"v49036-gamepad-first-key":"v49035-touch-first-key",
                        "RM11_V49036_HELD_KEY_DOWN_SENT_TO_LORIE="+
                        KeyEvent.keyCodeToString(keyCode)+"\\n"
                        +"RM11_V49036_INPUT_SOURCE="+(fromGamepad?"PHYSICAL_GAMEPAD":"TOUCH")+"\\n"
                        +"RM11_V49036_INPUT_BACKEND=EXISTING_HANDLEKEY\\n"
                        +"RM11_V49036_GAME_RESPONSE=DEVICE_VERIFICATION_REQUIRED");
            }
        }else if(!shouldDown && previous>=0){
            long started=touchKeyDownTimes.valueAt(previous);
            touchKeyDownTimes.delete(keyCode);
            if(getLorieView()!=null && getLorieView().connected()){
                long now=SystemClock.uptimeMillis();
                boolean accepted=getLorieView().sendKeyEvent(0,keyCode,false);
                if(accepted)keyboardForwardedUp++;
                if(inputTraceCount++<12 || !accepted)
                    OfflineDiagnosticJournal.record(this,"v49040-input-route",
                        "RM11_V49040_LORIE_KEY_UP="+KeyEvent.keyCodeToString(keyCode)
                        +"\\nRM11_V49040_LORIE_NATIVE_UP_ACCEPTED="+accepted
                        +"\\nRM11_V49040_UP_COUNT="+keyboardForwardedUp
                        +"\\nRM11_V49040_GAME_ACK=UNVERIFIED");
            }
        }
    }

    /** Every explicitly selected Win64 EXE now gets a full touch controller.
     *  Never activate in diagnostic probes, file browsing, or Wine desktop.
     *  XInput is preferred, with instant keyboard fallback if a game does not
     *  read the mapped XInput DLL. Per-game settings are stored locally.
     */
    private void installUniversalGamepad() {
        if(!directGameMode || requestedGame==null)return;
        try{
            xinputState=new RM11VirtualXInputV49037(this);
            universalPad=new RM11UniversalPadV49039(this,xinputState,
                (key,pressed)->sendCarXInputFromSource(key,pressed,false),
                requestedGame.toAbsolutePath().normalize().toString());
            addContentView(universalPad,new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
            gamepadDrive=new RM11GamepadDriveV49036((key,pressed)->{
                boolean fallback=universalPad!=null&&universalPad.useKeyboardFallback();
                if(fallback || !pressed)
                    sendCarXInputFromSource(key,pressed,true);
            },(control,defaultKey)->universalPad.resolvePhysicalBinding(control,defaultKey));
            universalPad.setOnPhysicalBindingsChanged(()->{
                if(gamepadDrive!=null)gamepadDrive.releaseAll();
            });
            gamepadInputManager=(InputManager)getSystemService(Context.INPUT_SERVICE);
            if(gamepadInputManager!=null)
                gamepadInputManager.registerInputDeviceListener(gamepadDisconnectListener,ui);
            refreshPhysicalGamepadPresence("INITIAL_ENUMERATION");
            OfflineDiagnosticJournal.record(this,"v49039-universal-pad",
                "RM11_V49039_UNIVERSAL_PAD_ENABLED=true\\n"
                +"RM11_V49039_SELECTED_GAME="+requestedGame.getFileName()+"\\n"
                +"RM11_V49039_INPUT=XINPUT_WITH_IMMEDIATE_KEYBOARD_FALLBACK\\n"
                +"RM11_V49039_ALL_BUTTONS_AND_DUAL_STICKS=true\\n"
                +"RM11_V49039_PER_GAME_LAYOUT_SETTINGS=true\\n"
                +"RM11_V49040_DEFAULT=KEYBOARD_COMPATIBILITY\\n"
                +"RM11_V49040_HOLD_BACKEND=LORIE_NATIVE_SEND_KEY_EVENT\\n"
                +"RM11_V49041_GAME_PROFILE="+RM11ControllerBindingsV49041.profileName(
                      requestedGame.toString())+"\\n"
                +"RM11_V49041_DEFAULT_MODE=AUTO_XINPUT_ELSE_KEYBOARD\\n"
                +"RM11_V49039_ACTUAL_GAME_INPUT_NEEDS_RUNTIME_VERIFICATION");
            ui.postDelayed(()->logVirtualXInputPoll("UNIVERSAL_FIRST"),18000);
            ui.postDelayed(()->logVirtualXInputPoll("UNIVERSAL_SECOND"),42000);
        }catch(Exception exception){
            OfflineDiagnosticJournal.record(this,"v49039-universal-pad",
                "RM11_V49039_INPUT_INITIALIZATION_FAILED="+
                exception.getClass().getSimpleName());
        }
    }

    private void installXInputVirtualGamepad() {
        if(gameTouchControls==null || !directGameMode)return;
        try {
            xinputState=new RM11VirtualXInputV49037(this);
            // Remove the old W/A/S/D touch keyboard UI entirely.
            gameTouchControls.releaseAll();
            gameTouchControls.setVisibility(View.GONE);
            xinputOverlay=new RM11VirtualGamepadOverlayV49037(this,xinputState);
            addContentView(xinputOverlay,new ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT));
            OfflineDiagnosticJournal.record(this,"v49037-xinput-overlay",
                    "RM11_V49037_XINPUT_TOUCH_CONTROLLER_CREATED=true\\n"
                    +"RM11_V49037_ANALOG_STICKS=true\\n"
                    +"RM11_V49037_ANALOG_LT_RT=true\\n"
                    +"RM11_V49037_KEYBOARD_WASD_OVERLAY_HIDDEN=true\\n"
                    +"RM11_V49037_SELECTED_CARX_ONLY=true");
            ui.postDelayed(()->logVirtualXInputPoll("FIRST"),22000);
            ui.postDelayed(()->logVirtualXInputPoll("SECOND"),45000);
        } catch(Exception problem) {
            OfflineDiagnosticJournal.record(this,"v49037-xinput-overlay",
                    "RM11_V49037_INIT_FAILED="+problem.getClass().getSimpleName());
        }
    }
    private void logVirtualXInputPoll(String stage) {
        if(shuttingDown || xinputState==null)return;
        OfflineDiagnosticJournal.record(this,"v49038-controller-status",
                "RM11_V49037_PROBE_STAGE="+stage+"\\n"
                +"RM11_V49037_NATIVE_DLL_GETSTATE_POLLS="+xinputState.readCount()+"\\n"
                +"RM11_V49042_NATIVE_DLL_GETCAPABILITIES_POLLS="+
                  xinputState.capabilitiesReadCount()+"\\n"
                +"RM11_V49037_NATIVE_GAME_INPUT_RECOGNITION="+
                  (xinputState.readCount()>0?"POLL_DETECTED":"NOT_DETECTED"));
    }

    private void installCarXExternalGamepad() {
        if(gameTouchControls==null)return; // only actual CarX Street, no other EXE
        gamepadDrive=new RM11GamepadDriveV49036(
                (code,pressed)->sendCarXInputFromSource(code,pressed,true));
        gamepadInputManager=(InputManager)getSystemService(Context.INPUT_SERVICE);
        if(gamepadInputManager!=null)
            gamepadInputManager.registerInputDeviceListener(gamepadDisconnectListener,ui);
        OfflineDiagnosticJournal.record(this,"v49036-gamepad-controls",
                "RM11_V49036_EXTERNAL_ANDROID_GAMEPAD_MAPPING_ENABLED=true\\n"
                +"RM11_V49036_AXIS=LEFT_STICK_X_Y_RT_LT_DPAD_HAT\\n"
                +"RM11_V49036_KEYS=W_A_S_D_SPACE_ESCAPE\\n"
                +"RM11_V49036_NATIVE_XINPUT_EMULATION=false\\n"
                +"RM11_V49036_TOUCH_GAMEPAD_HOLD_COEXISTENCE=true\\n"
                +"RM11_V49036_GAME_SCOPE=CARX_STREET_ONLY");
    }

    /** Enumerate already paired Bluetooth/USB controllers as well as hotplug.
     *  Never classify mice/keyboards as gamepads based only on a name. */
    private void refreshPhysicalGamepadPresence(String reason){
        boolean found=false;
        int count=0;
        for(int id:InputDevice.getDeviceIds()){
            InputDevice device=InputDevice.getDevice(id);
            if(device!=null && isGamepadInput(device,device.getSources())){
                found=true;
                count++;
            }
        }
        boolean changed=(physicalPadConnected!=found);
        physicalPadConnected=found;
        if(universalPad!=null)universalPad.setPhysicalControllerConnected(found);
        if(changed){
            if(!found){
                if(xinputState!=null)xinputState.physicalDisconnect();
                if(gamepadDrive!=null)gamepadDrive.releaseAll();
                lastGamepadDeviceId=-1;
                gamepadFirstLogged=false;
            }
        }
        if(changed || "INITIAL_ENUMERATION".equals(reason)){
            OfflineDiagnosticJournal.record(this,"v49042-pad-hotplug",
                "RM11_V49042_ANDROID_CONTROLLER_CONNECTED="+found+"\\n"
                +"RM11_V49042_CONTROLLER_COUNT="+count+"\\n"
                +"RM11_V49042_CHANGE_REASON="+reason+"\\n"
                +"RM11_V49042_TOUCH_CONTROLS_HIDDEN="+found+"\\n"
                +"RM11_V49042_GAME_DETECTS_PAD=NOT_YET_PROVEN");
        }
    }
    private static boolean isGamepadInput(InputDevice device,int source){
        if(device==null)return false;
        int combined=device.getSources()|source;
        return (combined&InputDevice.SOURCE_GAMEPAD)==InputDevice.SOURCE_GAMEPAD
                ||(combined&InputDevice.SOURCE_JOYSTICK)==InputDevice.SOURCE_JOYSTICK;
    }
    private boolean acceptsPhysicalGamepad(InputDevice device,int source){
        return gamepadDrive!=null && isGamepadInput(device,source);
    }
    private void firstGamepadSignal(int deviceId){
        lastGamepadDeviceId=deviceId;
        if(gamepadFirstLogged)return;
        gamepadFirstLogged=true;
        OfflineDiagnosticJournal.record(this,"v49036-gamepad-detected",
                "RM11_V49036_PHYSICAL_GAMEPAD_INPUT_DETECTED=true\\n"
                +"RM11_V49041_CONTROLLER_RECEIVED_BY_ANDROID=true\\n"
                +"RM11_V49041_NATIVE_XINPUT_REQUESTED=true\\n"
                +"RM11_V49041_GAME_XINPUT_RECOGNITION=READ_COUNTER_REQUIRED");
        Toast.makeText(this,"🎮 تم اكتشاف اليد — تأكد من استجابة اللعبة",Toast.LENGTH_SHORT).show();
    }
    private static float controllerTrigger(MotionEvent e,int axis){
        float value=e.getAxisValue(axis);
        InputDevice device=e.getDevice();
        if(device!=null){
            InputDevice.MotionRange range=device.getMotionRange(axis,e.getSource());
            if(range!=null && range.getMin()<=-0.5f && range.getMax()>=0.5f)
                value=(value+1f)/2f;
        }
        return Math.max(0f,Math.min(1f,value));
    }
    @Override public boolean dispatchGenericMotionEvent(MotionEvent event){
        if(xinputState!=null && event!=null
                &&event.getActionMasked()==MotionEvent.ACTION_MOVE
                &&isGamepadInput(event.getDevice(),event.getSource())
                &&(event.getSource()&InputDevice.SOURCE_JOYSTICK)
                     ==InputDevice.SOURCE_JOYSTICK){
            firstGamepadSignal(event.getDeviceId());
            float rightTrigger=Math.max(
                    controllerTrigger(event,MotionEvent.AXIS_RTRIGGER),
                    controllerTrigger(event,MotionEvent.AXIS_GAS));
            float leftTrigger=Math.max(
                    controllerTrigger(event,MotionEvent.AXIS_LTRIGGER),
                    controllerTrigger(event,MotionEvent.AXIS_BRAKE));
            float x=event.getAxisValue(MotionEvent.AXIS_X);
            float y=event.getAxisValue(MotionEvent.AXIS_Y);
            float hx=event.getAxisValue(MotionEvent.AXIS_HAT_X);
            float hy=event.getAxisValue(MotionEvent.AXIS_HAT_Y);
            xinputState.physicalAxes(x,y,
                    event.getAxisValue(MotionEvent.AXIS_Z),
                    event.getAxisValue(MotionEvent.AXIS_RZ),
                    leftTrigger,rightTrigger,hx,hy);
            if(gamepadDrive!=null){
                if(universalPad!=null&&universalPad.useKeyboardFallback())
                    gamepadDrive.axesFull(x,y,
                        event.getAxisValue(MotionEvent.AXIS_Z),
                        event.getAxisValue(MotionEvent.AXIS_RZ),
                        rightTrigger,leftTrigger,hx,hy);
                else gamepadDrive.releaseAll();
            }
            return true;
        }
        if(gamepadDrive!=null && event!=null
                &&event.getActionMasked()==MotionEvent.ACTION_MOVE
                &&acceptsPhysicalGamepad(event.getDevice(),event.getSource())
                &&(event.getSource()&InputDevice.SOURCE_JOYSTICK)
                      ==InputDevice.SOURCE_JOYSTICK){
            firstGamepadSignal(event.getDeviceId());
            float rt=Math.max(controllerTrigger(event,MotionEvent.AXIS_RTRIGGER),
                              controllerTrigger(event,MotionEvent.AXIS_GAS));
            float lt=Math.max(controllerTrigger(event,MotionEvent.AXIS_LTRIGGER),
                              controllerTrigger(event,MotionEvent.AXIS_BRAKE));
            gamepadDrive.axesFull(event.getAxisValue(MotionEvent.AXIS_X),
                              event.getAxisValue(MotionEvent.AXIS_Y),
                              event.getAxisValue(MotionEvent.AXIS_Z),
                              event.getAxisValue(MotionEvent.AXIS_RZ),
                              rt,lt,
                              event.getAxisValue(MotionEvent.AXIS_HAT_X),
                              event.getAxisValue(MotionEvent.AXIS_HAT_Y));
            return true;
        }
        return super.dispatchGenericMotionEvent(event);
    }
    @Override public boolean dispatchKeyEvent(KeyEvent event){
        if(xinputState!=null && event!=null
                &&isGamepadInput(event.getDevice(),event.getSource())
                &&RM11VirtualXInputV49037.handlesPhysicalButton(event.getKeyCode())
                &&(event.getAction()==KeyEvent.ACTION_DOWN
                    ||event.getAction()==KeyEvent.ACTION_UP)){
            firstGamepadSignal(event.getDeviceId());
            boolean pressed=event.getAction()==KeyEvent.ACTION_DOWN;
            xinputState.physicalKey(event.getKeyCode(),pressed);
            if(gamepadDrive!=null&&RM11GamepadDriveV49036.supportsButton(event.getKeyCode())){
                if(universalPad!=null&&universalPad.useKeyboardFallback())
                    gamepadDrive.button(event.getKeyCode(),pressed);
                else gamepadDrive.releaseAll();
            }
            return true;
        }
        if(gamepadDrive!=null && event!=null
                &&acceptsPhysicalGamepad(event.getDevice(),event.getSource())
                &&RM11GamepadDriveV49036.supportsButton(event.getKeyCode())
                &&(event.getAction()==KeyEvent.ACTION_DOWN
                    ||event.getAction()==KeyEvent.ACTION_UP)){
            firstGamepadSignal(event.getDeviceId());
            gamepadDrive.button(event.getKeyCode(),
                                event.getAction()==KeyEvent.ACTION_DOWN);
            return true;
        }
        return super.dispatchKeyEvent(event);
    }

    /** Adds only interactive button hitboxes over X11, not a full opaque UI. */
    private void installCarXTouchControls() {
        if(!directGameMode || requestedGame==null
                ||!com.rm11.autocore.runtime.CarXStreetDxvkV49032
                   .isSelectedCarXStreet(requestedGame))return;
        gameTouchControls=new RM11CarXTouchControls(this,
                this::sendCarXHeldKey,
                visible->OfflineDiagnosticJournal.record(this,
                        "v49035-touch-visibility",
                        "RM11_V49035_OVERLAY_VISIBLE="+visible+"\\n"
                        +"RM11_V49035_GAME=CARX_STREET_ONLY"));
        addContentView(gameTouchControls,new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT));
        OfflineDiagnosticJournal.record(this,"v49035-touch-controls",
                "RM11_V49035_CARX_CONTROLLER_VISIBLE=true\\n"
                +"RM11_V49035_KEYS=W,A,S,D,SPACE,ESC\\n"
                +"RM11_V49035_MULTITOUCH=SPLIT_MOTION_EVENTS\\n"
                +"RM11_V49035_HOLD_TO_KEY_DOWN_UP=true\\n"
                +"RM11_V49035_NO_GAME_OR_PREFIX_MODIFICATION=true\\n"
                +"RM11_V49035_VISUAL_OVERLAY_SCOPE=CARX_STREET_ONLY");
    }

    private void releaseAllCarXKeys() {
        if(universalPad!=null)universalPad.releaseAll();
        if(xinputOverlay!=null)xinputOverlay.releaseAll();
        if(xinputState!=null)xinputState.releaseAll();
        if(gameTouchControls!=null)gameTouchControls.releaseAll();
        if(gamepadDrive!=null)gamepadDrive.releaseAll();
        // Defensive cleanup if focus was lost while a button was being held.
        touchSourceHeld.clear();
        gamepadSourceHeld.clear();
        for(int i=touchKeyDownTimes.size()-1;i>=0;i--){
            int key=touchKeyDownTimes.keyAt(i);
            long started=touchKeyDownTimes.valueAt(i);
            if(getLorieView()!=null && getLorieView().connected()){
                long now=SystemClock.uptimeMillis();
                getLorieView().sendKeyEvent(0,key,false);
            }
        }
        touchKeyDownTimes.clear();
    }

    @Override public void onPause() {
        releaseAllCarXKeys();
        super.onPause();
    }
    @Override protected void onResume(){
        super.onResume();
        if(universalPad!=null)refreshPhysicalGamepadPresence("ACTIVITY_RESUMED");
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

    /**
     * First tap must reach Lorie unchanged. Snapshot the X11 root and Android
     * Surface after the user's exact blue-to-black transition. If both post
     * touch frames are black, surface a useful diagnostics action rather than
     * trapping the user behind the unresponsive Wine framebuffer.
     */
    @Override public boolean dispatchTouchEvent(android.view.MotionEvent event) {
        if(x11SurfaceTestMode) {
            // Diagnostic-only: consume the *whole gesture*, including UP,
            // POINTER_DOWN and MOVE. Do not affect desktop/game touch modes.
            if(event.getActionMasked()==android.view.MotionEvent.ACTION_DOWN
                    &&!firstProbeTouchCaptured) {
                firstProbeTouchCaptured=true;
                OfflineDiagnosticJournal.record(this,"v480-probe-touch-shield",
                        "RM11_V480_FIRST_DIAGNOSTIC_TOUCH=CONSUMED\n"
                        +"RM11_V480_X11_POINTER_EVENT_FORWARDED=false\n"
                        +"RM11_V480_WINE_AND_GAME_INPUT_UNCHANGED=true");
                ui.postDelayed(()->{
                    if(shuttingDown||isFinishing()||getLorieView()==null)return;
                    NativeDesktopVisualEvidence.auditSurface(getLorieView(),ui,pixels->
                        OfflineDiagnosticJournal.record(this,"v480-probe-after-touch",
                                "RM11_V480_TOUCH_CONSUMED_SURFACE_AFTER_500MS\n"+pixels));
                },500);
            }
            return true;
        }
        if(directGameMode
                && event.getActionMasked()==android.view.MotionEvent.ACTION_DOWN
                && !firstGameTouchCaptured) {
            firstGameTouchCaptured=true;
            OfflineDiagnosticJournal.record(this,"v482-game-touch-start",
                    "RM11_V482_GAME_TOUCH_PASSED_TO_LORIE=true\n"
                    +"RM11_V482_GAME_TOUCH_DIAGNOSTICS=ASYNC_PIXELCOPY_ONLY");
            // No interception: mouse/touch input MUST reach games normally.
            // Capture after touch independently, rather than assuming that a
            // black Surface proves Vulkan/WM loss.
            ui.postDelayed(()->captureGameSurfaceForTouch("AFTER_350MS"),350);
            ui.postDelayed(()->captureGameSurfaceForTouch("AFTER_1400MS"),1400);
        }
        if(event.getActionMasked()==android.view.MotionEvent.ACTION_DOWN
                && !directGameMode // a dark game frame is not desktop failure evidence
                &&wineGuiProcessStarted && !firstDesktopTouchCaptured) {
            firstDesktopTouchCaptured=true;
            ui.postDelayed(()->auditAfterFirstTouch("EARLY"),400);
            ui.postDelayed(()->auditAfterFirstTouch("SETTLED"),2200);
        }
        return super.dispatchTouchEvent(event);
    }

    private void captureGameSurfaceForTouch(String phase) {
        if(shuttingDown||isFinishing()||getLorieView()==null)return;
        exportWorker.execute(()->{
            String x11=NativeDesktopVisualEvidence.auditX11();
            ui.post(()->{
                if(shuttingDown||isFinishing()||getLorieView()==null)return;
                NativeDesktopVisualEvidence.auditSurface(getLorieView(),ui,pixels->{
                    if(shuttingDown||isFinishing())return;
                    OfflineDiagnosticJournal.record(this,
                            "BASELINE_BEFORE_TOUCH".equals(phase)
                                ?"v482-game-touch-baseline":"v482-game-touch-after",
                            "RM11_V482_GAME_TOUCH_SAMPLE="+phase+"\n"
                            +"RM11_V482_TOUCH_INTERCEPTION=false\n"
                            +"RM11_V482_X11:\n"+x11+"\n"
                            +"RM11_V482_ANDROID_SURFACE:\n"+pixels);
                });
            });
        });
    }

    private void auditAfterFirstTouch(String phase) {
        if(shuttingDown||isFinishing()||getLorieView()==null)return;
        exportWorker.execute(()->{
            String x11=NativeDesktopVisualEvidence.auditX11();
            ui.post(()->{
                if(shuttingDown||isFinishing()||getLorieView()==null)return;
                NativeDesktopVisualEvidence.auditSurface(getLorieView(),ui,pixels->{
                    if(shuttingDown||isFinishing())return;
                    String record="RM11_V452_AFTER_FIRST_TOUCH="+phase+"\n"+x11+"\n"+pixels;
                    lastVisualEvidence=record;
                    OfflineDiagnosticJournal.record(this,"v452-first-touch-visual",record);
                    java.util.regex.Matcher matcher=java.util.regex.Pattern
                            .compile("near_black_pixels=(\\d+)").matcher(pixels);
                    boolean black=false;
                    if(matcher.find()) {
                        try { black=Integer.parseInt(matcher.group(1))>=3980; }
                        catch(NumberFormatException ignored){}
                    }
                    consecutiveBlackTapFrames=black?consecutiveBlackTapFrames+1:0;
                    if(consecutiveBlackTapFrames>=2&&!blackScreenReported){
                        blackScreenReported=true;
                        OfflineDiagnosticJournal.record(this,"v452-screen-black",
                                "RM11_V452_BLACK_AFTER_TAP_CONFIRMED=true\n"+record);
                        showWineFailureOverlay("الشاشة صارت سوداء بعد اللمس.\n"
                                +"حفظنا فحص X11 وSurface، اضغط لفتح التقرير وحفظ ZIP.");
                    }
                });
            });
        });
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
        if(x11SurfaceTestMode) {
            lastStatus="X.Org متصل؛ فحص DRI3/Present ورسم خلفية خضراء بـX11 بدون Wine...";
            com.rm11.autocore.runtime.X11VulkanTouchStabilityAudit.inspectOnce(
                getApplicationContext());
            lastStatus="اكتمل اختبار ثبات Vulkan بعد لمس الشاشة؛ ارجع وصدّر ZIP.";
            OfflineDiagnosticJournal.record(this,"v480-native-x11-touch-stability-test-result",
                "RM11_V474_X11_WIRE_HANDSHAKE_ACCEPTED=true\n"
                +"RM11_V474_WINE_PROCESS_STARTED=false\n"
                +"RM11_V474_GAME_PROCESS_STARTED=false");
            runOnUiThread(()->showConnectionStatus(
                "اكتمل فحص Vulkan/X11. ارجع لمدير الملفات واحفظ تقرير ZIP."));
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
        if(sehProbeMode) {
            lastStatus="جاري فحص معالجة استثناءات Wine ARM64EC / FEX...";
            finalReport=fiberSehProbeMode
                    ?WineShellDesktopRunner.runFiberSehProbe(this,current,value->lastStatus=value)
                    :WineShellDesktopRunner.runSehProbe(this,current,value->lastStatus=value);
            OfflineDiagnosticJournal.record(this,"v460-seh-result",finalReport);
            final boolean testPassed=finalReport.contains(fiberSehProbeMode
                    ?"RM11_V461_FIBER_SEH_PASS=true":"RM11_V460_SEH_PASS=true");
            runOnUiThread(()->{
                if(isFinishing()||shuttingDown)return;
                new AlertDialog.Builder(this)
                    .setTitle((fiberSehProbeMode?"اختبار تبديل المكدس وSEH: ":"اختبار SEH الأساسي: ")
                            +(testPassed?"نجح":"فشل"))
                    .setMessage((testPassed
                        ?"تم التقاط استثناء x64 والتعامل وياه في Wine/FEX. "
                            +"هذا لا يعني أن خطأ Silksong انحل."
                        :"الاختبار المستقل لم يكتمل بنجاح. "
                            +"التقرير يحفظ رسائل Wine/FEX لمعرفة السبب.")
                        +"\n\nرمز الاختبار: RM11_V460_SEH_PASS="+testPassed)
                    .setPositiveButton("حفظ تقرير ZIP",(dialog,which)->exportZip())
                    .setNegativeButton("العودة لمدير الملفات",(dialog,which)->finish())
                    .setCancelable(false).show();
            });
            return;
        }
        if(directGameMode) {
            ui.postDelayed(()->captureGameSurfaceForTouch("BASELINE_BEFORE_TOUCH"),1000);
            OfflineDiagnosticJournal.record(this,"v455-game-display",
                    "RM11_V455_GAME_ONLY_NO_EXPLORER=true\n"
                    +"RM11_V455_SCREEN="+desktopW+"x"+desktopH);
            finalReport=WineShellDesktopRunner.runDirectGame(this,current,
                    value->{
                        lastStatus=value;
                        if(value.contains("تشغيل لعبة Windows مباشرة"))
                            wineGuiProcessStarted=true;
                        if("RM11_V457_NO_GAME_WINDOW_16S".equals(value))
                            ui.post(()->showGameNoWindowNotice(false));
                        if("RM11_V458_GAME_X11_CONNECTION_FAILED_16S".equals(value))
                            ui.post(()->showGameNoWindowNotice(true));
                        else if("RM11_V457_GAME_WINDOW_APPEARED".equals(value))
                            ui.post(this::clearGameNoWindowNotice);
                    },desktopW,desktopH,requestedGame,
                    ()->relay==null?"RM11_V458_RELAY_UNAVAILABLE":relay.diagnostics());
            ui.post(this::clearGameNoWindowNotice);
        } else {
            // Legacy desktop entry remains compiled for future re-enablement,
            // but is not reachable from the native game-first home screen.
            finalReport=WineShellDesktopRunner.run(this,current,
                    value->{
                        lastStatus=value;
                        if(value.contains("تشغيل سطح المكتب الحقيقي"))
                            wineGuiProcessStarted=true;
                    },desktopW,desktopH);
        }
        // No forced Winefile maximization or fake secondary desktop.
        // Store the failure reason separately: the large Wine server trace
        // may exceed one event's offline journal cap and hide decisive flags.
        // The helper may have exited with error but our genuine Winefile
        // recovery could still be serving visible X11 windows. Do not claim
        // the wineserver crashed merely because explorer.exe returned nonzero.
        boolean wineServerFailed=finalReport.contains("RM11_V451_WINESERVER_EXITED");
        boolean desktopFailed=wineServerFailed
                || finalReport.contains("RM11_V451_SHELL_START_FAILED")
                || finalReport.contains("RM11_V454_NO_USABLE_WINDOWS_AFTER_FALLBACK")
                || finalReport.contains("RM11_V455_GAME_EXEC_ERROR")
                || finalReport.contains("RM11_V455_GAME_WINESERVER_EXITED")
                || finalReport.contains("RM11_V455_GAME_NONZERO_EXIT")
                || finalReport.contains("RM11_V455_GAME_NO_VISIBLE_X11_WINDOW");
        if(desktopFailed) {
            String summary="RM11_V405_WINE_SERVER_STOPPED\n"
                    +"X.Org Lorie connection: functioning\n"
                    +"Wine server failure: "+wineServerFailed+"\n"
                    +"Wine desktop failure: "+desktopFailed+"\n"
                    +"Wine window status: unavailable\n"
                    +"Last activity status: "+lastStatus;
            OfflineDiagnosticJournal.record(this,"v405-wine-server-health",summary);
            lastStatus=wineServerFailed
                    ?"خادم Wine توقف، بينما X.Org يعمل. افتح التشخيص."
                    :directGameMode
                        ?"تعذّر إظهار نافذة اللعبة؛ افتح التشخيص لمعرفة السبب."
                        :"لم تظهر نوافذ سطح مكتب Wine بعد محاولة الإنقاذ. افتح التشخيص.";
            runOnUiThread(()->showWineFailureOverlay(lastStatus));
        } else {
            lastStatus="انتهت جلسة Wine؛ راجع التشخيص للتحقق.";
        }
        OfflineDiagnosticJournal.record(this,"v4-native-wine-session",finalReport);
    }

    /**
     * Real game-mode pending alert; only appears when the X11 root has no
     * viewable child after 16 seconds. It does not stop Wine or eat screen
     * interactions after a game window becomes visible.
     */
    private void showGameNoWindowNotice(boolean x11ConnectionFailed) {
        if(shuttingDown||isFinishing()||!directGameMode||gameNoWindowNotice!=null)return;
        LinearLayout panel=new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(15),dp(10),dp(15),dp(10));
        panel.setBackgroundColor(0xEF18283E);
        TextView detail=new TextView(this);
        detail.setText(x11ConnectionFailed
                ?"الاتصال بخادم عرض X11 يفشل أثناء تشغيل اللعبة.\n"
                    +"هذا عطل نقل/عرض محتمل، وليس مجرد انتظار تحميل اللعبة. احفظ ZIP."
                :"ما ظهرت نافذة اللعبة لحد الآن.\n"
                    +"يمكن الانتظار إذا اللعبة بعدها تُحمّل، أو احفظ ZIP للتشخيص.");
        detail.setTextSize(15);
        detail.setTextColor(Color.WHITE);
        panel.addView(detail,new LinearLayout.LayoutParams(-1,-2));
        Button save=new Button(this);
        save.setText("حفظ تقرير Wine/X11 بصيغة ZIP");
        save.setAllCaps(false);
        save.setTextSize(15);
        save.setOnClickListener(v->exportZip());
        panel.addView(save,new LinearLayout.LayoutParams(-1,dp(46)));
        Button dismiss=new Button(this);
        dismiss.setText("إخفاء التنبيه");
        dismiss.setAllCaps(false);
        dismiss.setOnClickListener(v->clearGameNoWindowNotice());
        panel.addView(dismiss,new LinearLayout.LayoutParams(-1,dp(43)));
        FrameLayout.LayoutParams position=new FrameLayout.LayoutParams(
                Math.min(getResources().getDisplayMetrics().widthPixels-dp(32),dp(600)),
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP|Gravity.CENTER_HORIZONTAL);
        position.topMargin=dp(12);
        gameNoWindowNotice=panel;
        addContentView(panel,position);
    }

    private void clearGameNoWindowNotice() {
        View notice=gameNoWindowNotice;
        gameNoWindowNotice=null;
        if(notice!=null && notice.getParent() instanceof ViewGroup)
            ((ViewGroup)notice.getParent()).removeView(notice);
    }

    private void showWineFailureOverlay(String message) {
        if(shuttingDown || isFinishing())return;
        // A Winefile failure should not strand the user on an empty white
        // X11 framebuffer. The native Nova desktop remains usable without
        // restarting or reinstalling the Wine prefix.
        // Do NOT overlay a still-running game for an isolated Winefile exit.
        if(novaDesktop!=null){
            Process running=selectedExeProcess;
            boolean activeGame=running!=null && running.isAlive();
            boolean serverDied=session!=null && session.hasServerCrashed();
            if(activeGame && !serverDied){
                OfflineDiagnosticJournal.record(this,"v441-winefile-warning",
                        "RM11_V441_RUNNING_EXE_PRESERVED\n"+message);
                return;
            }
            if(!novaDesktop.isOpen())novaDesktop.showDesktop();
            OfflineDiagnosticJournal.record(this,"v441-native-desktop-recovery",
                    "RM11_V441_AUTORETURNED_TO_NOVA_DESKTOP\n"
                    +"RM11_V441_WINEPREFIX_FILES_UNCHANGED=true\n"+message);
            Toast.makeText(this,
                    "واجهة Wine توقفت. رجعنا لسطح Nova؛ التشخيصات متاحة من START.",
                    Toast.LENGTH_LONG).show();
            return;
        }
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
                +lastFontSandboxEvidence+"\n"
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
                .setNeutralButton("فحص FreeType المعزول",(d,w)->{
                    // This is a separate Android process and never starts Wine.
                    // A crashing native ELF cannot run inside wineserver.
                    Intent probe=new Intent(this,RM11FontSandboxActivity.class);
                    startActivityForResult(probe,SEPARATE_FONT_SANDBOX);
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
        if(code==SEPARATE_FONT_SANDBOX){
            if(result==RESULT_OK && data!=null){
                String raw=data.getStringExtra(RM11FontSandboxActivity.EXTRA_RESULT);
                if(raw==null)raw="RM11_V445_NO_SANDBOX_REPORT";
                if(raw.length()>6000)raw=raw.substring(0,6000);
                lastFontSandboxEvidence=raw+"\n"+FontSandboxEvidence.classify(raw);
            }else{
                lastFontSandboxEvidence="RM11_V445_SANDBOX_NO_RESULT_OR_PROCESS_DIED";
            }
            OfflineDiagnosticJournal.record(this,"v445-android-process-font-audit",
                    lastFontSandboxEvidence);
            new AlertDialog.Builder(this).setTitle("نتيجة فحص FreeType المعزول")
                    .setMessage(lastFontSandboxEvidence)
                    .setPositiveButton("موافق",null).show();
            return;
        }
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
        releaseAllCarXKeys();
        if(xinputState!=null)try{xinputState.close();}catch(Exception ignored){} 
        if(gamepadInputManager!=null)
            gamepadInputManager.unregisterInputDeviceListener(gamepadDisconnectListener);
        shuttingDown=true;
        clearGameNoWindowNotice();
        ui.removeCallbacks(nativeReadiness);
        ui.removeCallbacks(startupCurtainProbe);
        if(startupCurtain!=null){
            startupCurtain.stop();
            startupCurtain=null;
        }
        if(controlPopup!=null)controlPopup.dismiss();
        if(novaDesktop!=null){novaDesktop.shutdown();novaDesktop=null;}
        if(Build.VERSION.SDK_INT>=33 && backControlsCallback!=null)
            getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(backControlsCallback);

        if(session!=null)session.close();
        if(relay!=null)relay.close();
        if(nativeServiceBound)unbindService(this);
        if(nativeServiceRequested)stopService(new Intent(this,RM11NativeX11Service.class));
        wineWorker.shutdownNow();
        Process runningExe=selectedExeProcess;
        if(runningExe!=null && runningExe.isAlive())runningExe.destroy();
        exeWorker.shutdownNow();
        exeProbeWorker.shutdownNow();
        frameFitWorker.shutdownNow();
        exportWorker.shutdown();
        super.onDestroy();
    }
}
