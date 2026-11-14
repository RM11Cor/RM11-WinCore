package com.r4.carxpc;

import android.content.Context;
import android.os.Build;
import android.view.Surface;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * CarX R3-C20: ONE-CLICK physical-Android orchestration of every existing
 * real on-device diagnostic gate. This is a unified test runner, NOT a
 * generalized Wine process emulator. No Linux x64 execve from Android,
 * no simulated PE execution, no DXVK fake triangle, no CarX gameplay claims.
 *
 * Stage 01: genuinely run packaged original FEXCore integration.
 * Stage 02: genuinely run original GNU x86 ld.so/libc 12-checkpoint sample.
 * Stage 03: check app-private original Wine RootFS presence.
 * Stage 04: inspect real Wine x64 ELF/ldso, kernel32 and DT_NEEDED.
 * Stage 05: genuinely run Android Vulkan driver probe.
 * Stage 06: genuinely submit/present existing Vulkan clear if surface ready.
 * Stage 07+: FAIL CLOSED for missing Android x86 Linux Wine process adapter.
 *
 * Each stage is individually reported with raw native evidence in one JSON.
 */
public final class CarXUnifiedBatch {
    private static final String SCHEMA="r4.carx.r3c20.android-oneclick-gates.v1";
    private static final String FEX_SHA="02e24ca5c01ed0c864466ed573db347336f70170";
    private static final String ROOTFS_NAME=GuestRootfsInstaller.ROOTFS_NAME;
    private CarXUnifiedBatch(){}

    private static final class Stage {
        final String id,category;
        final String status,reason;
        final JSONObject evidence;
        Stage(String i,String c,String s,String r,JSONObject e){
            id=i;category=c;status=s;reason=r;evidence=e;
        }
        JSONObject json() {
            JSONObject j=new JSONObject();
            try{
                j.put("id",id).put("category",category).put("status",status)
                 .put("reason",reason).put("evidence",evidence==null?JSONObject.NULL:evidence);
            }catch(Exception ignored){}
            return j;
        }
    }
    private static JSONObject error(Throwable e){
        JSONObject j=new JSONObject();
        try{
            j.put("exception_class",e.getClass().getName());
            j.put("message",String.valueOf(e.getMessage()));
        }catch(Exception ignored){}
        return j;
    }
    private static JSONObject data(String key,Object value){
        JSONObject j=new JSONObject();
        try{j.put(key,value);}catch(Exception ignored){}
        return j;
    }
    private static void add(List<Stage> steps,String id,String category,
                             String status,String reason,JSONObject evidence){
        steps.add(new Stage(id,category,status,reason,evidence));
    }

    public static JSONObject run(Context app, Surface surface){
        final List<Stage> stages=new ArrayList<>();
        boolean rootfsReady=false,elfReady=false,gnuPassed=false;
        boolean vulkanReady=false;
        JSONObject originalGnu=null;
        final Path appFiles=app.getFilesDir().toPath();

        // Source SHA is checked by original G0 runner's accepted original
        // native build and release pipeline. The entrypoint is real, never a
        // stub result or a test JSON fabricated by this class.
        try{
            JSONObject realFex=FexIntegrationProbe.run(app.getApplicationContext());
            boolean pass=realFex.optBoolean("success",false);
            add(stages,"01_FEXCORE_ORIGINAL", "GENUINE_ANDROID_X86_GUEST_EXECUTION",
                pass?"PASS":"FAIL",
                pass?"ORIGINAL_FEX_ANDROID_NATIVE_SAMPLE_RAN":
                     "ORIGINAL_FEX_ANDROID_NATIVE_SAMPLE_FAILED",
                realFex);
        }catch(Throwable e){
            add(stages,"01_FEXCORE_ORIGINAL","GENUINE_ANDROID_X86_GUEST_EXECUTION",
                "FAIL","FEXCORE_NATIVE_INVOCATION_THROWN",error(e));
        }
        try{
            originalGnu=FexIntegrationProbe.runOriginalLdsoContinuation(app.getApplicationContext());
            int passed=originalGnu.optInt("auto_batch_steps_passed",-1);
            int total=originalGnu.optInt("auto_batch_steps_total",-1);
            boolean batch=originalGnu.optBoolean("auto_batch_active",false);
            boolean exitProven=originalGnu.optBoolean(
                "auto_batch_terminal_original_guest_exit_group0_proven",false);
            gnuPassed=batch && passed==12 && total==12 && exitProven &&
                     originalGnu.optBoolean("success",false);
            add(stages,"02_GNU_LDSO_LIBC_12_OF_12",
                "GENUINE_SOURCE_PINNED_GUEST_GNU_SAMPLE",
                gnuPassed?"PASS":"FAIL",
                gnuPassed?"AUTHENTIC_ORIGINAL_X86_LIBC_12_CHECKPOINT_EXIT0":
                          "GNULDSO_AUTO_BATCH_NOT_COMPLETE_OR_REGRESSION",
                originalGnu);
        }catch(Throwable e){
            add(stages,"02_GNU_LDSO_LIBC_12_OF_12",
                "GENUINE_SOURCE_PINNED_GUEST_GNU_SAMPLE",
                "FAIL","GNULDSO_NATIVE_INVOCATION_THROWN",error(e));
        }

        final Path root=appFiles.resolve(ROOTFS_NAME);
        final Path receipt=root.resolve(".r4-rootfs-receipt");
        try{
            boolean exists=Files.isDirectory(root) && Files.isRegularFile(receipt);
            rootfsReady=exists;
            JSONObject e=new JSONObject();
            e.put("expected_source_archive_sha256",GuestRootfsInstaller.ARCHIVE_SHA256);
            e.put("app_private_storage",true);
            e.put("rootfs_directory_present",Files.isDirectory(root));
            e.put("source_receipt_present",Files.isRegularFile(receipt));
            e.put("compressed_archive_bundled_inside_apk",false);
            e.put("installed_guest_linux_executed",false);
            add(stages,"03_WINE_GUEST_ROOTFS",
                "ANDROID_APP_OWNED_GUEST_DATA",
                exists?"PASS":"BLOCKED",
                exists?"ORIGINAL_GUEST_SOURCE_RECEIPT_PRESENT_PENDING_FULL_HASH_AUDIT":
                       "ROOTFS_NOT_IMPORTED_USE_BUTTON_07_WITH_ORIGINAL_ARCHIVE",
                e);
        }catch(Throwable e){
            add(stages,"03_WINE_GUEST_ROOTFS","ANDROID_APP_OWNED_GUEST_DATA",
                "FAIL","ROOTFS_LOCAL_ACCESS_FAILED",error(e));
        }
        if(rootfsReady){
            try{
                WineGuestElfPreflight.Result x=WineGuestElfPreflight.inspect(appFiles);
                elfReady=x.realX86LinuxElfVerified&&x.guestInterpreterElfVerified &&
                    x.kernel32Pe64Amd64Verified&&x.immediateNeededLibrariesPresent;
                JSONObject e=new JSONObject();
                e.put("wine64_sha256",x.wineElfSha256);
                e.put("wine_interpreter",x.interpreter);
                e.put("gnu_ldso_sha256",x.interpreterElfSha256);
                e.put("kernel32_pe_sha256",x.kernel32PeSha256);
                e.put("wine64_pt_loads",x.winePtLoadSegments);
                e.put("gnu_ldso_pt_loads",x.interpreterPtLoadSegments);
                e.put("wine_dt_needed",new JSONArray(x.wineDtNeeded));
                e.put("unresolved_immediate_dt_needed",new JSONArray(x.unresolvedImmediateLibraries));
                e.put("wine_android_process_executed",false);
                add(stages,"04_WINE_ELF_AND_KERNEL32_AUTHENTIC",
                    "CRYPTOGRAPHIC_GUEST_ELF_AND_PE_SOURCE_PREFLIGHT",
                    elfReady?"PASS":"FAIL",
                    elfReady?"PINNED_WINE64_LDSO_KERNEL32_ELF_PE_VERIFIED":
                             "WINE_GUEST_ELF_OR_DT_NEEDED_NOT_READY",
                    e);
            }catch(Throwable e){
                add(stages,"04_WINE_ELF_AND_KERNEL32_AUTHENTIC",
                    "CRYPTOGRAPHIC_GUEST_ELF_AND_PE_SOURCE_PREFLIGHT",
                    "FAIL","WINE_GUEST_ELF_SOURCE_AUDIT_REJECTED",error(e));
            }
        }else{
            add(stages,"04_WINE_ELF_AND_KERNEL32_AUTHENTIC",
                "CRYPTOGRAPHIC_GUEST_ELF_AND_PE_SOURCE_PREFLIGHT",
                "NOT_REACHED","DEPENDENCY_03_GUEST_ROOTFS_MISSING",null);
        }

        try{
            String nativeJson=NativeRuntimeProbe.runNativeVulkanProbe();
            JSONObject d=new JSONObject(nativeJson);
            vulkanReady=d.optBoolean("ok",false);
            add(stages,"05_ANDROID_VULKAN_ICD",
                "GENUINE_ANDROID_GPU_DRIVER_PROBE",
                vulkanReady?"PASS":"FAIL",
                vulkanReady?"ANDROID_SYSTEM_VULKAN_DRIVER_AND_LOGICAL_DEVICE_READY":
                            "NATIVE_VULKAN_DEVICE_PROBE_FAILED",d);
        }catch(Throwable e){
            add(stages,"05_ANDROID_VULKAN_ICD",
                "GENUINE_ANDROID_GPU_DRIVER_PROBE","FAIL",
                "VULKAN_NATIVE_LOAD_OR_CREATE_DEVICE_THROWN",error(e));
        }

        if(surface!=null && surface.isValid()){
            try{
                JSONObject d=new JSONObject(NativeRuntimeProbe.runNativePresentationTest(surface));
                boolean ok=d.optBoolean("ok",false);
                add(stages,"06_ANDROID_VULKAN_SWAPCHAIN_CLEAR_PRESENT",
                    "GENUINE_VULKAN_WSI_CLEAR_PRESENT_NOT_GAME_GRAPHICS",
                    ok?"PASS":"FAIL",
                    ok?"VULKAN_SWAPCHAIN_CLEAR_PRESENTED_NO_TRIANGLE":
                       "VULKAN_SWAPCHAIN_CLEAR_PRESENTATION_FAILED",d);
            }catch(Throwable e){
                add(stages,"06_ANDROID_VULKAN_SWAPCHAIN_CLEAR_PRESENT",
                    "GENUINE_VULKAN_WSI_CLEAR_PRESENT_NOT_GAME_GRAPHICS",
                    "FAIL","VULKAN_WSI_NATIVE_INVOCATION_THROWN",error(e));
            }
        }else{
            add(stages,"06_ANDROID_VULKAN_SWAPCHAIN_CLEAR_PRESENT",
                "GENUINE_VULKAN_WSI_CLEAR_PRESENT_NOT_GAME_GRAPHICS",
                "BLOCKED","ANDROID_SURFACE_NOT_READY_IN_ONECLICK_SESSION",null);
        }

        // This repository currently exposes the fixed original G0 native FEX
        // executable test but not a verified general Linux x64 guest process
        // executor for all x86 syscalls, Wine's wineserver and fork/exec.
        // Stop here: NEVER pretend that wine64 ELF checksum or previously
        // accepted Linux ARM64 host Wine test proves Android Bionic execution.
        add(stages,"07_ANDROID_BIONIC_WINE_PROCESS_ADAPTER",
            "GUEST_LINUX_X64_ELF_PROCESS_AND_SYSCALL_RUNTIME",
            "BLOCKED",
            elfReady?
                "GENERALIZED_X86_LINUX_WINE_PROCESS_ADAPTER_NOT_IMPLEMENTED":
                "DEPENDENCY_04_WINE_ELF_NOT_VERIFIED_AND_GUEST_PROCESS_ADAPTER_MISSING",
            data("wine64_native_android_execution_proven",false));
        add(stages,"08_ANDROID_WINE_NTDLL_KERNEL32_WIN64_PE",
            "WIN64_GUEST_VM_TLS_WRITEFILE_EXECUTION",
            "NOT_REACHED","REQUIRES_07_REAL_WINE_PROCESS_AND_WIN64_PE_EXIT0",
            data("windows_pe_native_android_execution_proven",false));
        add(stages,"09_DXVK_D3D11_VULKAN_TRIANGLE",
            "REAL_WINDOWS_D3D11_TO_VULKAN_PRESENTATION",
            "NOT_REACHED","REQUIRES_08_REAL_WINDOWS_PE_AND_DXVK_INTEGRATION",
            data("graphics_triangle_rendered",false));
        add(stages,"10_CARX_STREET_PC_BOOT",
            "ACTUAL_SOURCE_OWNED_CARX_GAME_EXECUTION",
            "NOT_REACHED","REQUIRES_09_RENDERER_AND_GAME_RUNTIME",
            data("carx_game_boot_proven",false));

        JSONObject report=new JSONObject();
        try{
            JSONArray array=new JSONArray();
            int passes=0,failures=0,blocks=0;
            JSONObject firstStop=null,firstFailure=null;
            for(Stage stage:stages) {
                array.put(stage.json());
                if("PASS".equals(stage.status))passes++;
                if("FAIL".equals(stage.status))failures++;
                if("BLOCKED".equals(stage.status))blocks++;
                if(firstStop==null &&
                   ("FAIL".equals(stage.status)||"BLOCKED".equals(stage.status)))
                    firstStop=stage.json();
                if(firstFailure==null && "FAIL".equals(stage.status))
                    firstFailure=stage.json();
            }
            report.put("schema",SCHEMA);
            report.put("mode","ONE_CLICK_REAL_DEVICE_COMPONENT_BATCH");
            report.put("source_pinned_fex_git_commit",FEX_SHA);
            report.put("model",Build.MODEL);
            report.put("android_sdk",Build.VERSION.SDK_INT);
            report.put("host_abi",new JSONArray(Build.SUPPORTED_ABIS));
            report.put("total_stages",stages.size());
            report.put("pass_count",passes);
            report.put("fail_count",failures);
            report.put("block_count",blocks);
            report.put("first_failure",firstFailure==null?JSONObject.NULL:firstFailure);
            report.put("first_stop",firstStop==null?JSONObject.NULL:firstStop);
            report.put("stages",array);
            report.put("rootfs_metadata_verified",elfReady);
            report.put("original_gnu_12_steps_device_pass",gnuPassed);
            report.put("native_android_vulkan_device_ok",vulkanReady);
            report.put("native_android_wine_guest_process_executed",false);
            report.put("windows_pe_vm_tls_writefile_android_executed",false);
            report.put("dxvk_d3d11_triangle_rendered",false);
            report.put("carx_game_boot_proven",false);
            report.put("requires_additional_android_guest_process_adapter",true);
            report.put("note","Real FEX x86 guest sample, GNU 12-step, Wine ELF metadata and Vulkan tests are real. The generalized Wine x86 Linux process runtime, Win64 PE and CarX game launch are NOT implemented or claimed by this APK.");
        }catch(Exception e){
            try{report.put("fatal_json_error",String.valueOf(e));}
            catch(Exception ignored){}
        }
        return report;
    }
}
