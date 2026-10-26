package com.rm11.autocore;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.rm11.autocore.runtime.RuntimeLayout;
import com.rm11.autocore.runtime.WineNativeFontProbe;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Diagnostic Activity with AndroidManifest process=":rm11_font_sandbox".
 * The Wine desktop, Wine launcher, and X11 server run in other processes.
 *
 * Only loads the APK-signed NDK FreeType in THIS Android process. It neither
 * starts Wine/wineserver nor uses LD_PRELOAD or modifies any user files.
 * This is not a workaround for Wine's blank glyphs until device validation.
 */
public final class RM11FontSandboxActivity extends Activity {
    public static final String EXTRA_RESULT="rm11_font_sandbox_result";
    private static final int BACKGROUND=0xff09101a;
    private static final int TEXT=0xfff3f5fa;
    private static final int MUTED=0xffa8b6c9;
    private static final int RED=0xfff04452;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean sent=new AtomicBoolean(false);
    private TextView reportView;
    private volatile String report="RM11_V445_SANDBOX_NOT_RUN";
    private boolean ending;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        // Never use Wine/X11 views here. This window is ordinary Android UI.
        LinearLayout view=new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        view.setBackgroundColor(BACKGROUND);
        int d=(int)(16*getResources().getDisplayMetrics().density);
        view.setPadding(d,d,d,d);
        TextView title=new TextView(this);
        title.setText("RM11 | فحص FreeType المنعزل");
        title.setTextColor(TEXT);
        title.setTextSize(21);
        view.addView(title);
        TextView description=new TextView(this);
        description.setText("هذا فحص داخل عملية أندرويد مستقلة. ما يشغّل Wine، وما يغيّر الألعاب أو ملفات النظام. نتيجته لا تثبت ظهور نصوص Windows.");
        description.setTextColor(MUTED);
        description.setTextSize(14);
        description.setPadding(0,d/2,0,d/2);
        view.addView(description);
        ScrollView scroll=new ScrollView(this);
        reportView=new TextView(this);
        reportView.setText("جاري فحص المكتبة الموقّعة واسم التحميل...");
        reportView.setTextColor(TEXT);
        reportView.setTextSize(14);
        reportView.setTextIsSelectable(true);
        scroll.addView(reportView);
        view.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        Button finish=new Button(this);
        finish.setAllCaps(false);
        finish.setText("الرجوع إلى المحاكي");
        finish.setTextColor(Color.WHITE);
        finish.setBackgroundTintList(android.content.res.ColorStateList.valueOf(RED));
        finish.setOnClickListener(v->finish());
        view.addView(finish);
        setContentView(view);

        worker.execute(()->{
            String result;
            try {
                RuntimeLayout runtime=new RuntimeLayout(getFilesDir().toPath(),
                        new File(getApplicationInfo().nativeLibraryDir).toPath());
                String loader=WineNativeFontProbe.inspectLoaderBoundary(runtime);
                String glyph=WineNativeFontProbe.inspect(runtime);
                result="RM11_V445_SEPARATE_ANDROID_PROCESS=true\n"
                        +"RM11_V445_WINESERVER_NOT_INVOKED=true\n"
                        +"RM11_V445_WINE_LD_PRELOAD_NOT_USED=true\n"
                        +loader+glyph
                        +"RM11_V445_WINE_TEXT_RENDERING_NOT_PROVEN=true\n";
            }catch(Throwable failure){
                result="RM11_V445_SANDBOX_SAFE_FAILURE="
                        +failure.getClass().getSimpleName()+"\n"
                        +"RM11_V445_WINE_TEXT_RENDERING_NOT_PROVEN=true\n";
            }
            report=result;
            ui.post(()->{
                if(!ending && reportView!=null) reportView.setText(report);
            });
        });
    }

    @Override public void finish(){
        if(sent.compareAndSet(false,true)){
            Intent data=new Intent();
            data.putExtra(EXTRA_RESULT, report.length()>5000
                    ?report.substring(0,5000):report);
            setResult(RESULT_OK,data);
        }
        super.finish();
    }

    @Override protected void onDestroy(){
        ending=true;
        worker.shutdownNow();
        super.onDestroy();
    }
}
