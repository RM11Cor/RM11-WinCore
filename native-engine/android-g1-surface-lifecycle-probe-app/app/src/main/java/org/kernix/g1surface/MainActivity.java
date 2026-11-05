package org.kernix.g1surface;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * G1 Android Vulkan WSI surface lifetime gate.
 * First 48-frame real Vulkan presentation; force a NEW SurfaceView and a
 * different pixel extent; rerun 48 frames on new native ANativeWindow.
 * No FEX/Wine/Proton or games. Never claims visible animation from queueing.
 */
public final class MainActivity extends Activity {
    private static native int[] nativeProbe(Surface surface);
    private static final boolean LIB_OK;
    static {
        boolean ok=false;
        try { System.loadLibrary("kernix_g1_surface"); ok=true; }
        catch (UnsatisfiedLinkError ignored) {}
        LIB_OK=ok;
    }
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean running=new AtomicBoolean(false);
    private final AtomicInteger generation=new AtomicInteger(0);
    private LinearLayout root;
    private SurfaceView viewport;
    private TextView report;
    private Button start, recreate, rerun;
    private boolean firstPassed=false, replaced=false, secondPassed=false;
    private int firstWidth=-1, firstHeight=-1, newWidth=-1, newHeight=-1;
    private int oldGeneration=-1, newGeneration=-1, recreateEvents=0;
    private long totalRuns=0;
    private int heightDp=250;

    private int dp(int x) {return (int)(x*getResources().getDisplayMetrics().density+0.5f);}

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12),dp(14),dp(12),dp(10));
        root.setBackgroundColor(Color.rgb(12,19,30));
        TextView title=new TextView(this);
        title.setText("KERNIX / G1 SURFACE RECREATE");
        title.setTextColor(Color.WHITE);
        title.setTextSize(21);
        root.addView(title);
        TextView help=new TextView(this);
        help.setText("اختبار Vulkan متقدم: ١) شغّل 48 إطاراً ملوناً. ٢) أعد إنشاء سطح جديد بحجم مختلف. ٣) شغّل 48 إطاراً على السطح الجديد.\n"
            +"هذا يفحص دورة حياة Surface/Swapchain ولا يثبت استمرار الرسم بعد توقف الاختبار. "
            +"راقب تبدّل الألوان أثناء التنفيذ وصوّر فيديو إن أمكن. التطبيق مستقل ولا يعدّل نسخة KERNIX الأساسية.");
        help.setTextColor(0xffc8d9ef);help.setTextSize(13);
        root.addView(help);
        viewport=makeSurface();
        root.addView(viewport,new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,dp(heightDp)));
        start=new Button(this);
        start.setText("1 — عرض 48 إطاراً بالسطح الأول");
        start.setOnClickListener(v->run(false));
        root.addView(start);
        recreate=new Button(this);
        recreate.setText("2 — تدمير السطح وإنشاء سطح جديد بحجم آخر");
        recreate.setOnClickListener(v->replaceSurface());
        root.addView(recreate);
        rerun=new Button(this);
        rerun.setText("3 — عرض 48 إطاراً بالسطح الجديد");
        rerun.setOnClickListener(v->run(true));
        root.addView(rerun);
        report=new TextView(this);
        report.setTextColor(Color.WHITE);report.setTextSize(12);
        report.setTextIsSelectable(true);
        report.setText(LIB_OK
           ?"G1_SURFACE_READY=1\nابدأ بالزر الأول، ثم الثاني، ثم الثالث. افتح نتيجة الاختبار النهائية."
           :"G1_NATIVE_LOAD_FAILED=1");
        ScrollView scroll=new ScrollView(this);
        scroll.addView(report);
        root.addView(scroll,new LinearLayout.LayoutParams(
           LinearLayout.LayoutParams.MATCH_PARENT,0,1f));
        setContentView(root);
        start.setEnabled(LIB_OK);
        recreate.setEnabled(false);
        rerun.setEnabled(false);
    }

    private SurfaceView makeSurface() {
        SurfaceView s=new SurfaceView(this);
        s.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override public void surfaceCreated(SurfaceHolder h) {
                generation.incrementAndGet();
                if (replaced) { newGeneration=generation.get(); recreateEvents++; }
            }
            @Override public void surfaceChanged(SurfaceHolder h,int f,int w,int ht) {
                generation.incrementAndGet();
                if (replaced) {
                    newWidth=w; newHeight=ht; newGeneration=generation.get();
                }
            }
            @Override public void surfaceDestroyed(SurfaceHolder h) {
                generation.incrementAndGet();
                recreateEvents++;
            }
        });
        return s;
    }

    private void replaceSurface() {
        if (!firstPassed || running.get() || replaced) {
            report.setText("G1_RECREATE_NOT_ALLOWED: أتم الفحص الأول أولاً.");
            return;
        }
        oldGeneration=generation.get();
        replaced=true;
        recreateEvents=0;
        heightDp=175;
        root.removeView(viewport);
        viewport=makeSurface();
        root.addView(viewport,2,new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,dp(heightDp)));
        recreate.setEnabled(false);
        rerun.setEnabled(LIB_OK);
        report.setText("G1_SURFACE_RECREATED_REQUESTED=1\n"
            +"OLD_GENERATION="+oldGeneration+"\n"
            +"السطح الجديد ارتفاعه مختلف. اضغط 3 بعد ظهوره.");
    }

    private void run(boolean postRecreate) {
        if (!LIB_OK || running.get())return;
        if (postRecreate && !firstPassed) {
            report.setText("G1_FIRST_SESSION_MISSING=1");return;
        }
        if (postRecreate && !replaced) {
            report.setText("G1_NEW_SURFACE_NOT_CREATED=1");return;
        }
        if (!postRecreate && firstPassed) {
            report.setText("G1_ALREADY_PASSED_FIRST_SESSION=1");return;
        }
        final Surface surface=viewport.getHolder().getSurface();
        if (surface==null || !surface.isValid()) {
            report.setText("G1_SURFACE_INVALID=1\nالسطح بعده ما تجهز.");return;
        }
        if (!running.compareAndSet(false,true))return;
        final int g=generation.get();
        final long runIndex=++totalRuns;
        start.setEnabled(false);recreate.setEnabled(false);rerun.setEnabled(false);
        report.setText("G1_SURFACE_RUN="+runIndex+"\nG1_RUNNING=1\nراقب الألوان المتغيرة الآن...");
        worker.execute(()->{
            int[] output=null;
            String exception="";
            long started=android.os.SystemClock.elapsedRealtime();
            try {
                if (g==generation.get() && surface.isValid())output=nativeProbe(surface);
                else exception="SURFACE_CHANGED_BEFORE_NATIVE";
            }catch(Throwable t){exception=t.getClass().getSimpleName();}
            final int[] result=output;
            final String err=exception;
            final long elapsed=android.os.SystemClock.elapsedRealtime()-started;
            runOnUiThread(()->{
                running.set(false);
                if (isFinishing()||isDestroyed())return;
                if (g!=generation.get()||!surface.isValid()) {
                    report.setText("G1_SURFACE_CHANGED_DURING_NATIVE=1\n"
                        +"Old GPU report discarded; do not count as PASS.");
                    start.setEnabled(!firstPassed && LIB_OK);
                    rerun.setEnabled(replaced && firstPassed && LIB_OK);
                    return;
                }
                if (result==null||result.length!=12) {
                    report.setText("G1_NATIVE_RESULT_INVALID=1\n"+err);
                    start.setEnabled(!firstPassed && LIB_OK);
                    rerun.setEnabled(replaced && firstPassed && LIB_OK);
                    return;
                }
                boolean good=result[1]==0&&result[8]==0&&result[9]==1
                          &&result[10]==48&&result[11]==48;
                if (!postRecreate) {
                    firstPassed=good;
                    firstWidth=result[2];firstHeight=result[3];
                    recreate.setEnabled(good);
                    start.setEnabled(!good&&LIB_OK);
                }else {
                    newWidth=result[2];newHeight=result[3];
                    secondPassed=good;
                    rerun.setEnabled(!good&&LIB_OK);
                }
                boolean extentChanged=firstWidth>0&&newWidth>0
                           &&(firstWidth!=newWidth||firstHeight!=newHeight);
                boolean all=firstPassed&&secondPassed&&replaced
                         &&extentChanged&&newGeneration>oldGeneration
                         &&recreateEvents>=1;
                report.setText(
                   "G1_SURFACE_RECREATION_TWO_SESSION_PASS="+(all?1:0)
                   +"\nG1_FIRST_QUEUE_PASS="+(firstPassed?1:0)
                   +"\nG1_AFTER_NEW_SURFACE_QUEUE_PASS="+(secondPassed?1:0)
                   +"\nG1_STAGE="+(result[1]==0?"VK_SUCCESS_48_FRAMES":
                       "FAILED_STAGE_CODE_"+result[1])
                   +"\nVK_RESULT="+result[8]
                   +"\nSWAPCHAIN_CREATE_FAILED_MINUS3="+(result[1]==8&&result[8]==-3?1:0)
                   +"\nFRAMES_ATTEMPTED="+result[10]
                   +"\nFRAMES_COMPLETED="+result[11]
                   +"\nFIRST_WINDOW="+firstWidth+"x"+firstHeight
                   +"\nSECOND_WINDOW="+newWidth+"x"+newHeight
                   +"\nWINDOW_EXTENT_CHANGED="+(extentChanged?1:0)
                   +"\nNEW_SURFACE_CREATED="+(replaced?1:0)
                   +"\nSURFACE_LIFECYCLE_EVENTS="+recreateEvents
                   +"\nSURFACE_GENERATION="+generation.get()
                   +"\nOLD_GENERATION="+oldGeneration
                   +"\nNEW_GENERATION="+newGeneration
                   +"\nELAPSED_MS="+elapsed
                   +"\nVISIBLE_ANIMATION_NOT_ATTESTED=1"
                   +"\nPERSISTENT_RENDER_LOOP=0"
                   +"\nWINE_PROTON_GAMES_EXECUTED=0");
            });
        });
    }

    @Override protected void onPause() {
        generation.incrementAndGet();
        super.onPause();
    }
    @Override protected void onDestroy() {
        generation.incrementAndGet();
        worker.shutdownNow();
        super.onDestroy();
    }
}
