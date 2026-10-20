package com.rm11.autocore;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Isolated activity: existing device probe and game files are untouched. */
public final class VulkanRenderActivity extends Activity implements SurfaceHolder.Callback {
    private SurfaceView surfaceView;
    private TextView report;
    private Button runButton;
    private volatile boolean running;
    private volatile boolean surfaceReady;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(0xFF0A0F1B);
        getWindow().setNavigationBarColor(0xFF0A0F1B);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0A0F1B);
        root.setPadding(dp(12), dp(12), dp(12), dp(12));
        TextView header = new TextView(this);
        header.setText("RM11 • Vulkan GPU Surface Render v2.4.11");
        header.setTextSize(19);
        header.setTextColor(Color.WHITE);
        header.setGravity(Gravity.CENTER);
        root.addView(header, new LinearLayout.LayoutParams(-1, -2));
        surfaceView = new SurfaceView(this);
        surfaceView.getHolder().addCallback(this);
        root.addView(surfaceView, new LinearLayout.LayoutParams(-1, 0, 3f));
        runButton = new Button(this);
        runButton.setText("ابدأ عرض 180 إطار Vulkan حقيقي");
        runButton.setEnabled(false);
        runButton.setOnClickListener(v -> startTest());
        root.addView(runButton);
        report = new TextView(this);
        report.setTextColor(0xFFD1E0F5);
        report.setTextSize(14);
        report.setPadding(dp(8), dp(8), dp(8), dp(8));
        report.setText("بانتظار Surface... لا يتم تعديل الألعاب أو تجربة تشغيل EXE.");
        root.addView(report, new LinearLayout.LayoutParams(-1, 0, 2f));
        setContentView(root);
    }

    private int dp(int v) { return Math.round(getResources().getDisplayMetrics().density * v); }

    private void startTest() {
        if (running || !surfaceReady) return;
        running = true;
        runButton.setEnabled(false);
        report.setText("جاري إنشاء Surface وSwapchain وعرض ألوان متحركة عبر GPU...");
        final android.view.Surface surface = surfaceView.getHolder().getSurface();
        Thread worker = new Thread(() -> {
            String result = VulkanFrameRenderer.run(surface, 180);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                report.setText(result);
                running = false;
                runButton.setEnabled(surfaceReady);
            });
        }, "rm11-vulkan-render-test");
        worker.start();
    }

    @Override public void surfaceCreated(SurfaceHolder holder) { surfaceReady = true; runButton.setEnabled(!running); }
    @Override public void surfaceChanged(SurfaceHolder holder, int format, int w, int h) {
        surfaceReady = w > 0 && h > 0;
        runButton.setEnabled(surfaceReady && !running);
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder) {
        surfaceReady = false;
        runButton.setEnabled(false);
    }
}
