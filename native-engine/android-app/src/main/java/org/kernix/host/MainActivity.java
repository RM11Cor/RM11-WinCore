package org.kernix.host;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import java.io.InputStream;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Button;
import android.view.SurfaceView;
import android.view.SurfaceHolder;

/**
 * KERNIX-native proof app. This is NOT a Windows emulator yet.
 * It shows facts from the actual Android system Vulkan loader.
 */
public final class MainActivity extends Activity {
    private static native int[] nativeHostProbe();
    private static native String nativeGpuProbe();
    private static native String nativeSurfaceProbe(android.view.Surface surface);
    private TextView details;
    private TextView gameDetails;
    private TextView surfaceDetails;
    private static final int PICK_EXE = 702;
    private static final boolean NATIVE_AVAILABLE;
    private static final String NATIVE_ERROR;

    static {
        boolean loaded = false;
        String error = "";
        try {
            System.loadLibrary("kernix_host");
            System.loadLibrary("kernix_host_jni");
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            error = e.getMessage();
        }
        NATIVE_AVAILABLE = loaded;
        NATIVE_ERROR = error;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout main = new LinearLayout(this);
        main.setOrientation(LinearLayout.VERTICAL);
        main.setPadding(28, 40, 28, 28);
        main.setBackgroundColor(Color.rgb(12, 19, 30));
        TextView title = new TextView(this);
        title.setText("KERNIX");
        title.setTextSize(32);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        main.addView(title);
        TextView subtitle = new TextView(this);
        subtitle.setText("Independent ARM64 Host · Technical Preview");
        subtitle.setTextColor(0xffa1b7d1);
        subtitle.setTextSize(15);
        main.addView(subtitle);
        details = new TextView(this);
        details.setTextColor(Color.WHITE);
        details.setTextSize(15);
        details.setPadding(0, 24, 0, 24);
        main.addView(details);
        Button probe = new Button(this);
        probe.setText("Check native KERNIX host");
        probe.setOnClickListener(v -> refresh());
        main.addView(probe);
        Button gpuButton = new Button(this);
        gpuButton.setText("Enumerate real Vulkan GPU");
        gpuButton.setOnClickListener(v -> {
            if (!NATIVE_AVAILABLE) {
                details.setText("Native host unavailable: " + NATIVE_ERROR);
                return;
            }
            try {
                details.setText(nativeGpuProbe());
            } catch (Throwable e) {
                details.setText("GPU enumeration failed: " + e.getClass().getSimpleName());
            }
        });
        main.addView(gpuButton);
        SurfaceView nativeSurface = new SurfaceView(this);
        nativeSurface.setLayoutParams(new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 180));
        main.addView(nativeSurface);
        surfaceDetails = new TextView(this);
        surfaceDetails.setTextColor(Color.WHITE);
        surfaceDetails.setText("Android Vulkan window: not probed");
        main.addView(surfaceDetails);
        nativeSurface.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override public void surfaceCreated(SurfaceHolder holder) {
                // The native bootstrap owns only a temporary VkSurfaceKHR.
                // It never retains Android's Surface across lifecycle events.
                if (!NATIVE_AVAILABLE) {
                    surfaceDetails.setText("Native library unavailable");
                    return;
                }
                try {
                    surfaceDetails.setText(nativeSurfaceProbe(holder.getSurface()));
                } catch (Throwable e) {
                    surfaceDetails.setText("Vulkan surface bootstrap error: "
                            + e.getClass().getSimpleName());
                }
            }
            @Override public void surfaceChanged(SurfaceHolder holder, int format,
                                                 int width, int height) {}
            @Override public void surfaceDestroyed(SurfaceHolder holder) {
                surfaceDetails.setText("Android surface destroyed (no native handle retained)");
            }
        });
        Button choose = new Button(this);
        choose.setText("Inspect Windows EXE (read-only)");
        choose.setOnClickListener(v -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            picker.setType("*/*");
            picker.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(picker, PICK_EXE);
        });
        main.addView(choose);
        gameDetails = new TextView(this);
        gameDetails.setTextColor(Color.WHITE);
        gameDetails.setTextSize(15);
        gameDetails.setPadding(0, 14, 0, 16);
        gameDetails.setText("No EXE inspected. Only static PE metadata will be read.");
        main.addView(gameDetails);
        TextView warning = new TextView(this);
        warning.setText("Host verification only. Wine, FEX, games and Vulkan rendering are not integrated yet.");
        warning.setTextColor(0xffffc77c);
        warning.setPadding(0, 20, 0, 0);
        main.addView(warning);
        setContentView(main);
        refresh();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_EXE || resultCode != RESULT_OK || data == null) return;
        Uri selected = data.getData();
        if (selected == null) return;
        try (InputStream stream = getContentResolver().openInputStream(selected)) {
            gameDetails.setText(GameInspector.inspect(stream));
        } catch (Exception e) {
            gameDetails.setText("Unable to inspect EXE: " + e.getMessage());
        }
    }

    private void refresh() {
        if (!NATIVE_AVAILABLE) {
            details.setText("Native host unavailable: " + NATIVE_ERROR);
            return;
        }
        try {
            int[] report = nativeHostProbe();
            if (report == null || report.length != 5 || report[0] != 1 || report[1] != 1 || report[4] != 16) {
                details.setText("Host ABI mismatch or invalid response");
                return;
            }
            int flags = report[2];
            int v = report[3];
            String version = ((v >> 22) & 0x7f) + "." + ((v >> 12) & 0x3ff) + "." + (v & 0xfff);
            details.setText("Host ABI: " + report[0] + "\n"
                    + "Android ARM64: " + ((flags & 1) != 0 ? "reported" : "unavailable") + "\n"
                    + "Vulkan system loader: " + ((flags & 2) != 0 ? "loaded" : "not found") + "\n"
                    + "Vulkan version query: " + ((flags & 4) != 0 ? version : "not available") + "\n"
                    + "Vulkan API 1.1+: " + ((flags & 8) != 0 ? "loader reports yes" : "not confirmed") + "\n"
                    + "GPU/swapchain/game validation: NOT TESTED");
        } catch (Throwable e) {
            details.setText("Native host failed to load or run: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
    }
}
