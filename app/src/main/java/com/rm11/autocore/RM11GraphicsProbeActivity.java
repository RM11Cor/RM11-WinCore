package com.rm11.autocore;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.graphics.Typeface;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.rm11.autocore.runtime.EngineVNextGraphicsManifestGate;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

/**
 * Explicit, opt-in on-device diagnostics; isolated Android process to contain
 * a driver dlopen crash. NO game, Wine prefix, GPU override, or HAL mutation.
 * Loading a library does not prove Vulkan device creation or Android frames.
 */
public final class RM11GraphicsProbeActivity extends Activity {
    private TextView output;
    private final Handler main=new Handler(Looper.getMainLooper());

    private static String explain(Throwable e){
        String raw=e.getMessage();
        if(raw==null)raw="";
        // Do not leak app-private paths or arbitrary debug text to screen/ZIP.
        raw=raw.replaceAll("/data/[^\\s:,;\\]\\)]+","[app-private]");
        raw=raw.replaceAll("[\\r\\n\\t]+"," ");
        if(raw.length()>350)raw=raw.substring(0,350);
        return e.getClass().getSimpleName()+": "+raw;
    }
    private void log(String item){
        main.post(()->output.append(item+"\n"));
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(28,25,28,25);
        root.setBackgroundColor(0xff111824);
        TextView title=new TextView(this);
        title.setText("RM11 — Graphics Integrity & Turnip Loader");
        title.setTextSize(19);
        title.setTextColor(0xffffffff);
        root.addView(title);
        Button start=new Button(this);
        start.setText("Run isolated graphics preflight");
        root.addView(start);
        Button exit=new Button(this);
        exit.setText("Back (no game changes)");
        exit.setOnClickListener(v->finish());
        root.addView(exit);
        ScrollView scroll=new ScrollView(this);
        output=new TextView(this);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextColor(0xffbfe2ff);
        output.setTextIsSelectable(true);
        output.setTextSize(13);
        scroll.addView(output);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(root);
        start.setOnClickListener(v->{
            start.setEnabled(false);
            output.setText("RM11_GRAPHICS_DEVICE_PROBE_V1\n");
            Thread worker=new Thread(()->{
                log("SDK="+Build.VERSION.SDK_INT);
                log("Purpose=SIGNED_APK_BYTES_AND_NATIVE_DLOPEN_ONLY");
                log("WINE_DXVK_GAME_FRAME=NOT_TESTED");
                boolean manifest=false;
                try{
                    EngineVNextGraphicsManifestGate.Verified v=
                            EngineVNextGraphicsManifestGate.inspect(
                                getApplicationContext());
                    manifest=true;
                    log("SIGNED_GRAPHICS_FILES=PASS count="+
                            v.hashVerifiedComponents);
                    Path driver=v.signedNativeDirectory.resolve(
                            "libvulkan_freedreno.so");
                    try{
                        System.load(driver.toString());
                        log("TURNIP_BIONIC_DLOPEN=SUCCESS");
                        log("TURNIP_VULKAN_DEVICE_ENUMERATION=NOT_TESTED");
                        log("TURNIP_DXVK_WINE_HOOK=NOT_ACTIVE");
                        log("ANDROID_FRAME_PROOF=UNVERIFIED");
                    }catch(LinkageError|SecurityException failure){
                        log("TURNIP_BIONIC_DLOPEN=FAILED");
                        log("LOADER_ERROR="+explain(failure));
                    }
                }catch(Exception e){
                    log("SIGNED_GRAPHICS_FILES=FAIL");
                    log("INTEGRITY_ERROR="+explain(e));
                }
                log("ENGINE_ACTIVATION=DISABLED");
                log("NO_GAME_FILES_OR_PREFIX_MODIFIED=true");
                log("PROBE_COMPLETE=YES");
                main.post(()->start.setEnabled(true));
            },"rm11-isolated-graphics-probe");
            worker.setDaemon(true);
            worker.start();
        });
    }
}
