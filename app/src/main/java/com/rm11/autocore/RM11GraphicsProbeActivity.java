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
import com.rm11.autocore.runtime.KernixEngineQualificationV49090;
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
        start.setText("Run Turnip Vulkan device test (isolated)");
        root.addView(start);
        Button gpuButton=new Button(this);
        gpuButton.setText("Run real GPU command and buffer readback (isolated)");
        root.addView(gpuButton);
        Button surfaceButton=new Button(this);
        surfaceButton.setText("Test PRIVATE Turnip Android screen (60 frames)");
        surfaceButton.setOnClickListener(v->startActivity(
                new android.content.Intent(this,RM11TurnipSurfaceActivity.class)));
        root.addView(surfaceButton);
        Button bridgeButton=new Button(this);
        bridgeButton.setText("Test GPU color to Android Surface via CPU bridge (no WSI)");
        bridgeButton.setOnClickListener(v->startActivity(new android.content.Intent(
                this,RM11TurnipBufferSurfaceActivity.class)));
        root.addView(bridgeButton);
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
        gpuButton.setOnClickListener(v->{
            KernixEngineQualificationV49090.recordProbeAttempt(
                getApplicationContext(),"NATIVE_VULKAN_GPU_QUEUE",
                "RUNNING","NATIVE_GPU_PROBE_STARTED");
            gpuButton.setEnabled(false);
            output.append("RM11_PRIVATE_TURNIP_GPU_READBACK_V1\n");
            getSharedPreferences("rm11-vulkan-probe",MODE_PRIVATE).edit()
                    .putString("last_gpu_state","RUNNING").commit();
            Thread proofWorker=new Thread(()->{
                try {
                    EngineVNextGraphicsManifestGate.Verified verified=
                            EngineVNextGraphicsManifestGate.inspect(getApplicationContext());
                    log("SIGNED_GRAPHICS_FILES=PASS count="+verified.hashVerifiedComponents);
                    org.json.JSONObject r=RM11TurnipGpuProof.run(
                            verified.signedNativeDirectory.resolve("libvulkan_freedreno.so"));
                    log("GPU_PROOF_STAGE="+r.optString("stage","UNKNOWN"));
                    log("GPU_INSTANCE_RESULT="+r.optInt("instance_result",-999));
                    log("GPU_DEVICE_RESULT="+r.optInt("device_result",-999));
                    log("GPU_VENDOR_ID="+r.optLong("vendor_id",0));
                    log("GPU_DEVICE_ID="+r.optLong("device_id",0));
                    log("GPU_QUEUE_RESULT="+r.optInt("queue_result",-999));
                    log("GPU_QUEUE_SUBMIT_SUCCESS="+
                            r.optBoolean("queue_submit_success",false));
                    log("GPU_FENCE_COMPLETED="+r.optBoolean("fence_completed",false));
                    log("GPU_BUFFER_READBACK_MATCH="+
                            r.optBoolean("gpu_buffer_readback_match",false));
                    // Save a genuine device-only GPU command proof. This is
                    // not X11, Wine, DirectX or visible-frame certification.
                    boolean receipt=KernixEngineQualificationV49090
                        .recordGpuQueue(getApplicationContext(),r);
                    log("KERNIX_ENGINE_GPU_QUEUE_RECEIPT="+
                        (receipt?"RECORDED":"NOT_RECORDED"));
                    KernixEngineQualificationV49090.recordProbeAttempt(
                        getApplicationContext(),"NATIVE_VULKAN_GPU_QUEUE",
                        receipt?"PASS":"FAIL",r.optString("stage","NATIVE_UNKNOWN"));
                    boolean gpuProof=r.optBoolean("queue_submit_success",false)
                            &&r.optBoolean("fence_completed",false)
                            &&r.optBoolean("gpu_buffer_readback_match",false);
                    log("GPU_COMMAND_EXECUTION_PROOF="+(gpuProof?"PASS":"NOT_PROVEN"));
                } catch (Throwable error) {
                    log("GPU_COMMAND_EXECUTION_PROOF=ERROR");
                    log("GPU_PROOF_ERROR="+explain(error));
                    KernixEngineQualificationV49090.recordProbeAttempt(
                        getApplicationContext(),"NATIVE_VULKAN_GPU_QUEUE",
                        "FAIL",error.getClass().getSimpleName());
                }
                log("ANDROID_SURFACE_FRAME_PROOF=NOT_TESTED");
                log("X11_WINE_DXVK_RENDER_PROOF=NOT_TESTED");
                log("ENGINE_ACTIVATION=DISABLED");
                log("GPU_PROOF_COMPLETE=YES");
                getSharedPreferences("rm11-vulkan-probe",MODE_PRIVATE).edit()
                        .putString("last_gpu_state","COMPLETE").apply();
                main.post(()->gpuButton.setEnabled(true));
            },"rm11-gpu-command-test");
            proofWorker.setDaemon(true);
            proofWorker.start();
        });
        String previous=getSharedPreferences("rm11-vulkan-probe",MODE_PRIVATE)
                .getString("last_state","NEVER_STARTED");
        if("RUNNING".equals(previous))
            output.setText("PREVIOUS_TURNIP_NATIVE_TEST_INTERRUPTED_OR_CRASHED\n"
                    +"ENGINE_ACTIVATION=DISABLED\n");
        start.setOnClickListener(v->{
            start.setEnabled(false);
            output.setText("RM11_GRAPHICS_DEVICE_PROBE_V2\n");
            getSharedPreferences("rm11-vulkan-probe",MODE_PRIVATE)
                .edit().putString("last_state","RUNNING").commit();
            Thread worker=new Thread(()->{
                log("SDK="+Build.VERSION.SDK_INT);
                log("Purpose=SIGNED_APK_BYTES_AND_NATIVE_DLOPEN_ONLY");
                log("WINE_DXVK_GAME_FRAME=NOT_TESTED");
                try{
                    EngineVNextGraphicsManifestGate.Verified verifiedGraphics=
                            EngineVNextGraphicsManifestGate.inspect(
                                getApplicationContext());
                    log("SIGNED_GRAPHICS_FILES=PASS count="+
                            verifiedGraphics.hashVerifiedComponents);
                    Path driver=verifiedGraphics.signedNativeDirectory.resolve(
                            "libvulkan_freedreno.so");
                    try{
                        System.load(driver.toString());
                        log("TURNIP_BIONIC_DLOPEN=SUCCESS");
                        log("TURNIP_ICD_HARDWARE_PROBE=STARTED");
                        // Native driver access can abort inside an Android
                        // GPU/vendor dependency; this Activity is in its
                        // own :rm11_graphics_probe process on purpose.
                        org.json.JSONObject icd=RM11TurnipIcdProbe.inspect(driver);
                        log("TURNIP_ICD_STAGE="+icd.optString("stage","UNKNOWN"));
                        log("TURNIP_ICD_NEGOTIATE_RESULT="+
                                icd.optInt("icd_negotiate_result",-999));
                        log("TURNIP_ICD_INTERFACE_VERSION="+
                                icd.optInt("icd_interface_version",0));
                        log("TURNIP_VK_CREATE_INSTANCE="+
                                icd.optInt("vk_create_instance",-999));
                        log("TURNIP_VK_ENUMERATE_DEVICES="+
                                icd.optInt("vk_enumerate_physical_devices",-999));
                        log("TURNIP_PHYSICAL_DEVICE_COUNT="+
                                icd.optInt("physical_device_count",0));
                        log("TURNIP_GPU_VENDOR_ID="+
                                icd.optLong("vendor_id",0));
                        log("TURNIP_GPU_DEVICE_ID="+
                                icd.optLong("device_id",0));
                        log("TURNIP_GPU_API_VERSION_RAW="+
                                icd.optLong("api_version",0));
                        log("TURNIP_GRAPHICS_QUEUE_PRESENT="+
                                icd.optBoolean("graphics_queue_present",false));
                        log("TURNIP_VK_CREATE_LOGICAL_DEVICE="+
                                icd.optInt("vk_create_logical_device",-999));
                        boolean enumerated=icd.optInt("vk_enumerate_physical_devices",-999)==0
                                &&icd.optInt("physical_device_count",0)>0;
                        log("TURNIP_VULKAN_DEVICE_ENUMERATION="+
                                (enumerated?"SUCCESS":"NOT_PROVEN"));
                        log("TURNIP_DXVK_WINE_HOOK=NOT_ACTIVE");
                        log("ANDROID_FRAME_PROOF=UNVERIFIED");
                    }catch(LinkageError failure){
                        log("TURNIP_ICD_HARDWARE_PROBE=LINKER_ERROR");
                        log("LOADER_ERROR="+explain(failure));
                    }catch(Exception failure){
                        log("TURNIP_ICD_HARDWARE_PROBE=EXCEPTION");
                        log("ICD_PROBE_ERROR="+explain(failure));
                    }
                }catch(Exception e){
                    log("SIGNED_GRAPHICS_FILES=FAIL");
                    log("INTEGRITY_ERROR="+explain(e));
                }
                log("ENGINE_ACTIVATION=DISABLED");
                log("NO_GAME_FILES_OR_PREFIX_MODIFIED=true");
                log("PROBE_COMPLETE=YES");
                getSharedPreferences("rm11-vulkan-probe",MODE_PRIVATE)
                    .edit().putString("last_state","COMPLETE").apply();
                main.post(()->start.setEnabled(true));
            },"rm11-isolated-graphics-probe");
            worker.setDaemon(true);
            worker.start();
        });
    }
}
