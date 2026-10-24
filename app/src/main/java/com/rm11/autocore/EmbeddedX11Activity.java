package com.rm11.autocore;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import au.com.darkside.xserver.XServer;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import com.rm11.autocore.runtime.WineX11EndpointProbe;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * First real app-owned X11 server/view integration (X11 core and basic GDI).
 *
 * The view is the display; not a screenshot, a synthetic Windows window, a
 * remote service, or a second Android app. Wine uses localhost DISPLAY=:2.
 *
 * The pinned Java XServer is MIT licensed and remains loopback only.
 * It does not implement all modern X extensions and is not a GPU compositor.
 */
public final class EmbeddedX11Activity extends Activity {
    private static final int PICK_EXE = 2821;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private XServer server;
    private Button pick;
    private Button closeDesktop;
    private volatile ExternalExeRunnerV270.GuiSessionGate currentSession;
    private TextView status;
    private boolean busy;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setStatusBarColor(Color.rgb(8, 13, 21));
        getWindow().setNavigationBarColor(Color.rgb(8, 13, 21));

        FrameLayout viewport = new FrameLayout(this);
        viewport.setBackgroundColor(Color.rgb(15, 20, 30));

        server = new XServer(this, WineX11EndpointProbe.EMBEDDED_PORT, null);
        // Defense in depth: only the loopback IPv4 host is accepted.
        server.setAccessControl(true);
        server.getAccessControlHosts().add(0x7f000001);
        // ScreenView starts its X11 listener when Android assigns a real
        // display size. Keep the activity in foreground for Wine lifetime.
        FrameLayout.LayoutParams full = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        viewport.addView(server.getScreen(), full);

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        controls.setGravity(Gravity.CENTER_VERTICAL);
        controls.setBackgroundColor(0xE8122036);
        int pad = Math.round(getResources().getDisplayMetrics().density * 8);
        controls.setPadding(pad, pad, pad, pad);

        pick = new Button(this);
        pick.setAllCaps(false);
        pick.setText("اختيار EXE وعرض نافذته هنا");
        pick.setOnClickListener(v -> chooseExe());
        controls.addView(pick, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        closeDesktop = new Button(this);
        closeDesktop.setText("إغلاق سطح المكتب وحفظ التقرير");
        closeDesktop.setAllCaps(false);
        closeDesktop.setEnabled(false);
        closeDesktop.setOnClickListener(v -> {
            ExternalExeRunnerV270.GuiSessionGate gate = currentSession;
            if (gate != null) gate.requestClose();
            closeDesktop.setEnabled(false);
            status.setText("يجري إغلاق جلسة Wine وحفظ تقرير التشخيص...");
        });
        controls.addView(closeDesktop, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        status = new TextView(this);
        status.setTextSize(12);
        status.setTextColor(Color.WHITE);
        status.setTypeface(Typeface.MONOSPACE);
        status.setText("RM11 embedded X11 :2 | نافذة Windows غير مختبرة بعد");
        status.setMaxLines(3);
        status.setPadding(pad, 0, pad, 0);
        controls.addView(status, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 2f));
        FrameLayout.LayoutParams bottom = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM);
        viewport.addView(controls, bottom);
        setContentView(viewport);
    }

    private void chooseExe() {
        if (busy) return;
        pick.setEnabled(false);
        status.setText("اختَر EXE صغيراً مستقلاً (حتى 16 MiB). هذه شاشة X11 داخل RM11.");
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivityForResult(intent, PICK_EXE);
        } catch (Exception error) {
            status.setText("منتقي الملفات فشل: " + error.getClass().getSimpleName());
            pick.setEnabled(true);
        }
    }

    @Override protected void onActivityResult(int req, int code, Intent data) {
        super.onActivityResult(req, code, data);
        if (req != PICK_EXE) return;
        if (code != RESULT_OK || data == null || data.getData() == null) {
            status.setText("لم يتم اختيار EXE. شاشة العرض الداخلية ما زالت تعمل.");
            pick.setEnabled(true);
            return;
        }
        busy = true;
        pick.setEnabled(false);
        closeDesktop.setEnabled(true);
        Uri selected = data.getData();
        final ExternalExeRunnerV270.GuiSessionGate gate =
                new ExternalExeRunnerV270.GuiSessionGate();
        currentSession = gate;
        status.setText("RM11 DISPLAY=:2 | بعد انتهاء EXE يبقى سطح المكتب مفتوحاً حتى تضغط زر الإغلاق (بحد أقصى 5 دقائق).");
        executor.execute(() -> {
            final String report = ExternalExeRunnerV270.runEmbedded(this, selected, gate);
            OfflineDiagnosticJournal.record(this, "wine-embedded-x11-v282", report);
            String summary = summarize(report);
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                busy = false;
                currentSession = null;
                closeDesktop.setEnabled(false);
                status.setText(summary);
                pick.setEnabled(true);
            });
        });
    }

    private static String summarize(String report) {
        StringBuilder s = new StringBuilder("RM11 embedded X11: ");
        s.append(report.contains("APP_EMBEDDED_X11_DISPLAY_2: WIRE_HANDSHAKE_ACCEPTED")
                ? "PROTOCOL_OK" : "WIRE_NOT_ACCEPTED");
        s.append(" | GUI_CREATE=")
                .append(report.contains("Raw external GUI CreateWindow marker captured: YES") ? "YES" : "NO");
        s.append(" | GDI_PAINT=")
                .append(report.contains("Observed GDI paint marker in bounded Wine log: YES") ? "YES" : "NO");
        s.append(" | TOUCH=")
                .append(report.contains("Observed user touch marker in bounded Wine log: YES") ? "YES" : "NO");
        s.append(" | راجع تقرير التشخيص من الشاشة الرئيسية. النجاح الحقيقي يتطلب رؤية نافذة Windows.");
        return s.toString();
    }

    @Override protected void onDestroy() {
        ExternalExeRunnerV270.GuiSessionGate gate = currentSession;
        if (gate != null) gate.requestClose();
        if (server != null) server.stop();
        executor.shutdownNow();
        super.onDestroy();
    }
}
