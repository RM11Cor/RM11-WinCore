package org.kernix.host;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Button;

/**
 * KERNIX-native proof app. This is NOT a Windows emulator yet.
 * It shows facts from the actual Android system Vulkan loader.
 */
public final class MainActivity extends Activity {
    private static native int[] nativeHostProbe();
    private TextView details;

    static {
        System.loadLibrary("kernix_host");
        System.loadLibrary("kernix_host_jni");
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
        TextView warning = new TextView(this);
        warning.setText("Host verification only. Wine, FEX, games and Vulkan rendering are not integrated yet.");
        warning.setTextColor(0xffffc77c);
        warning.setPadding(0, 20, 0, 0);
        main.addView(warning);
        setContentView(main);
        refresh();
    }

    private void refresh() {
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
