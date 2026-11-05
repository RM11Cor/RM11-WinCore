package org.kernix.g1steady;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * KERNIX G1 — independently installable Android Vulkan WSI diagnostics.
 * Never launches x86, Wine, Proton or games; does not alter the stable APK.
 * A vkQueuePresentKHR success only proves queued presentation, not pixels
 * displayed by SurfaceFlinger or persistent game rendering.
 */
public final class MainActivity extends Activity {
    private static native int[] nativeProbe(Surface surface);
    private static native void nativeCancel();
    private static final String[] STAGES = {
        "VK_SUCCESS_180_FRAMES_ONE_SWAPCHAIN",
        "INVALID_SURFACE_OR_ARGS",
        "vkCreateInstance",
        "vkCreateAndroidSurfaceKHR",
        "vkEnumeratePhysicalDevices",
        "find graphics/present queue",
        "VK_KHR_swapchain, surface format/caps",
        "vkCreateDevice",
        "vkCreateSwapchainKHR",
        "vkAcquireNextImageKHR / vkQueueSubmit / vkQueuePresentKHR",
        "CANCELLED_BY_LIFECYCLE"
    };
    private final ExecutorService gpuWorker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger generation = new AtomicInteger();
    private final AtomicInteger touches = new AtomicInteger();
    private final AtomicInteger sessions = new AtomicInteger();
    private SurfaceView viewport;
    private TextView details;
    private Button first;
    private Button afterTouch;
    private boolean firstQueuedPass;
    private boolean afterTouchQueuedPass;
    private boolean nativeLoaded;

    private static final boolean NATIVE_LOADED;
    static {
        boolean ok=false;
        try {
            System.loadLibrary("kernix_g1_steady");
            ok=true;
        } catch (UnsatisfiedLinkError ignored) {
            // Do not invent a successful JNI load.
        }
        NATIVE_LOADED=ok;
    }

    private int dp(int n) {
        return (int)(getResources().getDisplayMetrics().density*n+0.5f);
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        nativeLoaded = NATIVE_LOADED;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(14),dp(18),dp(14),dp(14));
        root.setBackgroundColor(Color.rgb(12,19,30));
        TextView title = new TextView(this);
        title.setText("KERNIX / G1 STEADY 180");
        title.setTextColor(Color.WHITE);
        title.setTextSize(23);
        root.addView(title);
        TextView help = new TextView(this);
        help.setText("راقب تبدل 4 ألوان بوضوح أثناء اختبار 180 إطاراً محدوداً (بضع ثوانٍ)، وصوّر فيديو. لا يدل نجاح الأرقام وحده على رؤية البكسلات.\n" + "فحص رسوميات منفصل: إنشاء Vulkan Surface/Swapchain وإرسال 180 إطاراً متغيّر اللون، ثم إعادة الفحص بعد لمس الشاشة.\n"
                +"مهم: إرسال الإطار لا يثبت عرضه فعلياً، واختفاء اللون بعد الفحص القصير متوقع. "
                +"لا تشغيل لـWine أو الألعاب. لا يغير KERNIX v0.27.");
        help.setTextColor(0xffc8d9ef);
        help.setTextSize(13);
        root.addView(help);

        viewport = new SurfaceView(this);
        viewport.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,dp(250)));
        root.addView(viewport);
        viewport.setOnTouchListener((View view, MotionEvent e) -> {
            if (e.getActionMasked()==MotionEvent.ACTION_DOWN) {
                int n=touches.incrementAndGet();
                details.setText("Surface touch events: "+n
                    +"\nاضغط زر إعادة الفحص بعد اللمس. لا نعيد إنشاء Swapchain تلقائياً داخل حدث اللمس.");
            }
            return true;
        });
        viewport.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override public void surfaceCreated(SurfaceHolder h) {
                generation.incrementAndGet();
                showLifecycle("surfaceCreated");
            }
            @Override public void surfaceChanged(SurfaceHolder h,int format,int w,int hgt) {
                generation.incrementAndGet();
                showLifecycle("surfaceChanged "+w+"x"+hgt);
            }
            @Override public void surfaceDestroyed(SurfaceHolder h) {
                generation.incrementAndGet();
                if (nativeLoaded) nativeCancel();
                showLifecycle("surfaceDestroyed: cancelling active Vulkan session");
            }
        });

        first = new Button(this);
        first.setText("1 — شغّل 180 إطاراً على Swapchain واحد");
        first.setOnClickListener(v -> runProbe(false));
        root.addView(first);
        afterTouch = new Button(this);
        afterTouch.setText("2 — كرر 180 إطاراً بعد لمس الشاشة");
        afterTouch.setOnClickListener(v -> runProbe(true));
        root.addView(afterTouch);
        details = new TextView(this);
        details.setTextColor(Color.WHITE);
        details.setTextSize(13);
        details.setTextIsSelectable(true);
        details.setPadding(0,dp(16),0,dp(18));
        details.setText(nativeLoaded
            ? "ابدأ ثم راقب الأحمر والأخضر والأزرق والأصفر مباشرة. صوّر فيديو أثناء تغير الألوان، ثم المس السطح وكرر."
            : "G1_NATIVE_LIBRARY_LOAD_FAILED: مكتبة Vulkan الأصلية غير متوفرة. ممنوع إعلان النجاح.");
        ScrollView log = new ScrollView(this);
        log.setFillViewport(false);
        log.addView(details);
        root.addView(log,new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,0,1f));
        setContentView(root);
        first.setEnabled(nativeLoaded);
        afterTouch.setEnabled(nativeLoaded);
    }

    private void showLifecycle(String event) {
        if (details != null && !isFinishing() && !isDestroyed()) {
            details.setText("G1_SURFACE_EVENT="+event+"\nGeneration="+generation.get()
                +"\nLast GPU result is invalid after Surface lifecycle changes.");
        }
    }
    private void runProbe(boolean requiresTouch) {
        if (!nativeLoaded) {
            details.setText("G1_NATIVE_LIBRARY_LOAD_FAILED");return;
        }
        if (requiresTouch && touches.get()==0) {
            details.setText("G1_POST_TOUCH_NOT_RUN: المس مساحة SurfaceView أولاً.");return;
        }
        Surface surface = viewport.getHolder().getSurface();
        if (surface==null || !surface.isValid()) {
            details.setText("G1_SURFACE_INVALID: لا يمكن تشغيل Vulkan على Surface مدمر.");return;
        }
        if (!running.compareAndSet(false,true))return;
        final int initialGeneration = generation.get();
        final int touchSnapshot = touches.get();
        final int runIndex = sessions.incrementAndGet();
        first.setEnabled(false);
        afterTouch.setEnabled(false);
        details.setText("G1_RUNNING session="+runIndex
                +"\nTesting native Vulkan off the Android UI thread...");
        gpuWorker.execute(() -> {
            final long start=android.os.SystemClock.elapsedRealtime();
            int[] result=null;
            String error="";
            try {
                if (initialGeneration==generation.get() && surface.isValid())
                    result=nativeProbe(surface);
                else error="SURFACE_INVALIDATED_BEFORE_NATIVE_CALL";
            } catch(Throwable failure) {
                error=failure.getClass().getSimpleName();
            }
            final long elapsed=android.os.SystemClock.elapsedRealtime()-start;
            final int[] nativeResult=result;
            final String nativeError=error;
            runOnUiThread(() -> {
                running.set(false);
                if (isDestroyed() || isFinishing())return;
                first.setEnabled(nativeLoaded);
                afterTouch.setEnabled(nativeLoaded);
                if (initialGeneration!=generation.get() || !surface.isValid()) {
                    details.setText("G1_SURFACE_CHANGED_DURING_RUN=1\n"
                        +"Discarded stale GPU result. A new surface requires a new probe.");
                    return;
                }
                if (nativeResult==null || nativeResult.length!=12) {
                    details.setText("G1_NATIVE_PROBE_NO_VALID_REPORT=1\n"+nativeError);
                    return;
                }
                boolean queued=nativeResult[1]==0 &&
                    nativeResult[9]==1 &&
                    nativeResult[10]==180 && nativeResult[11]==180;
                if (requiresTouch && touchSnapshot>0) afterTouchQueuedPass=queued;
                else if (!requiresTouch) firstQueuedPass=queued;
                String stage=nativeResult[1]>=0 && nativeResult[1]<STAGES.length
                    ? STAGES[nativeResult[1]] : "UNKNOWN_STATUS";
                details.setText(
                    "G1_STEADY_180_FRAMES_QUEUED="+(queued?1:0)
                    +"\nG1_POST_TOUCH_SESSION="+(requiresTouch?1:0)
                    +"\nG1_STAGE="+stage
                    +"\nVK_RESULT="+nativeResult[8]
                    +"\nSWAPCHAIN_CREATE_FAILED_MINUS3="+
                        (nativeResult[1]==8 && nativeResult[8]==-3?1:0)
                    +"\nWINDOW="+nativeResult[2]+"x"+nativeResult[3]
                    +"\nIMAGES_REQUESTED="+nativeResult[4]
                    +"\nFORMAT="+nativeResult[5]
                    +"\nPRESENT_MODE="+nativeResult[6]
                    +"\nQUEUE_FAMILY="+nativeResult[7]
                    +"\nFRAMES_ATTEMPTED="+nativeResult[10]
                    +"\nFRAMES_COMPLETED="+nativeResult[11]
                    +"\nSURFACE_TOUCHES="+touchSnapshot
                    +"\nSURFACE_GENERATION="+initialGeneration
                    +"\nELAPSED_MS="+elapsed
                    +"\nG1_STEADY_TWO_SESSIONS_QUEUE_PASS="+
                        (firstQueuedPass&&afterTouchQueuedPass?1:0)
                    +"\nPIXELS_VISIBLY_PRESENTED_NOT_ATTESTED=1"
                    +"\nBOUNDED_ONE_SWAPCHAIN_RENDER_LOOP=1\\nUNBOUNDED_RENDERER_PROVEN=0"
                    +"\nWINE_OR_WINDOWS_PE_OR_GAMES_EXECUTED=0");
            });
        });
    }
    @Override protected void onPause() {
        generation.incrementAndGet();
        if (nativeLoaded) nativeCancel();
        super.onPause();
    }
    @Override protected void onDestroy() {
        generation.incrementAndGet();
        if (nativeLoaded) nativeCancel();
        gpuWorker.shutdownNow();
        super.onDestroy();
    }
}
