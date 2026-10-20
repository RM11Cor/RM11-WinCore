package com.rm11.autocore;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** One screen and one unified report covering five independently labelled checks. */
public final class VulkanSuiteActivity extends Activity implements SurfaceHolder.Callback {
    private SurfaceView output;
    private TextView report;
    private Button start;
    private Button share;
    private volatile boolean busy;
    private volatile boolean surfaceReady;
    private boolean automaticStartDone;
    private String lastReport="";

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setStatusBarColor(0xFF0A0F1B);
        getWindow().setNavigationBarColor(0xFF0A0F1B);
        LinearLayout content=new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(12),dp(12),dp(12),dp(12));
        content.setBackgroundColor(0xFF0A0F1B);
        TextView title=new TextView(this);
        title.setText("RM11 • GPU 5-in-1 Vulkan Test v2.4.12");
        title.setTextColor(Color.WHITE);
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER);
        content.addView(title,new LinearLayout.LayoutParams(-1,-2));
        TextView note=new TextView(this);
        note.setText("Shader • Triangle • Compute • GPU Timing • DXVK Prerequisites\nDXVK وWindows EXE لا يُشغّلان بهذا الفحص");
        note.setTextSize(12); note.setTextColor(0xFFB0C4DB);
        note.setGravity(Gravity.CENTER);
        content.addView(note,new LinearLayout.LayoutParams(-1,-2));
        output=new SurfaceView(this);
        output.getHolder().addCallback(this);
        content.addView(output,new LinearLayout.LayoutParams(-1,0,3f));
        start=new Button(this);
        start.setText("إعادة تشغيل الفحص الموحد");
        start.setEnabled(false);
        start.setOnClickListener(v -> runSuite());
        content.addView(start,new LinearLayout.LayoutParams(-1,-2));
        share=new Button(this);
        share.setText("مشاركة التقرير الكامل مرة واحدة");
        share.setEnabled(false);
        share.setOnClickListener(v -> {
            if(lastReport.isEmpty())return;
            Intent intent=new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_TEXT,lastReport);
            startActivity(Intent.createChooser(intent,"مشاركة فحص GPU الشامل"));
        });
        content.addView(share,new LinearLayout.LayoutParams(-1,-2));
        ScrollView scroller=new ScrollView(this);
        report=new TextView(this);
        report.setText("بانتظار Surface؛ سيبدأ الاختبار تلقائياً عند الجاهزية.");
        report.setTextSize(13);
        report.setTextColor(0xFFDEE8F4);
        report.setTextIsSelectable(true);
        report.setPadding(dp(8),dp(8),dp(8),dp(8));
        scroller.addView(report);
        content.addView(scroller,new LinearLayout.LayoutParams(-1,0,2f));
        setContentView(content);
    }
    private int dp(int v){return Math.round(getResources().getDisplayMetrics().density*v);}
    private void runSuite(){
        if(busy||!surfaceReady)return;
        busy=true;
        start.setEnabled(false);
        share.setEnabled(false);
        report.setText("يُنفذ الآن اختبار GPU الشامل؛ 240 إطاراً، والنتيجة ستظهر كتقرير واحد...");
        final Surface surface=output.getHolder().getSurface();
        new Thread(() -> {
            final String data=VulkanSuite.run(surface);
            runOnUiThread(() -> {
                busy=false;
                if(isFinishing()||isDestroyed())return;
                lastReport=data;
                report.setText(data);
                share.setEnabled(true);
                start.setEnabled(surfaceReady);
            });
        }, "rm11-suite-worker").start();
    }
    @Override public void surfaceCreated(SurfaceHolder holder){surfaceReady=true;start.setEnabled(!busy);}
    @Override public void surfaceChanged(SurfaceHolder holder,int format,int w,int h){
        surfaceReady=w>0&&h>0;
        start.setEnabled(surfaceReady&&!busy);
        if(surfaceReady&&!automaticStartDone){automaticStartDone=true;runSuite();}
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder){surfaceReady=false;start.setEnabled(false);}
}
