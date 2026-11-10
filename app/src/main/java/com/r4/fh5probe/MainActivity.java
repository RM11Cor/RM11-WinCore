package com.r4.fh5probe;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static native String nativeProbe();
    static { System.loadLibrary("fh5probe"); }

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView scroll = new ScrollView(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int)(18 * getResources().getDisplayMetrics().density);
        box.setPadding(pad,pad,pad,pad);
        scroll.addView(box);
        TextView header = new TextView(this);
        header.setText("FH5 Native Port — M19\nVulkan ARM64 capability diagnostic\n\nNot the Forza Horizon 5 game.");
        header.setTextSize(19);
        header.setTypeface(null,Typeface.BOLD);
        header.setTextColor(Color.rgb(20,30,46));
        box.addView(header);
        TextView output = new TextView(this);
        output.setTextSize(15);
        output.setTextIsSelectable(true);
        output.setPadding(0,pad,0,pad);
        output.setText("Tap the button to inspect your GPU. No internet or game files required.");
        Button run = new Button(this);
        run.setText("Inspect Vulkan GPU");
        box.addView(run, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        box.addView(output);
        run.setOnClickListener(v -> {
            run.setEnabled(false);
            output.setText("Checking Vulkan driver...");
            new Thread(() -> {
                String result;
                try { result = nativeProbe(); }
                catch(Throwable err) { result = "Native probe failed: " + err; }
                final String message = result;
                runOnUiThread(() -> { output.setText(message); run.setEnabled(true); });
            },"fh5-vulkan-probe").start();
        });
        setContentView(scroll);
    }
}
