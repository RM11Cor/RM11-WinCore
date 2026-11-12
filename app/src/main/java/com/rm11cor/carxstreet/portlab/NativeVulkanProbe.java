package com.rm11cor.carxstreet.portlab;

import org.json.JSONObject;

/**
 * Device-side native ARM64 Vulkan bootstrap measurement. The library is
 * original independent code, and is NOT the proprietary CarX game runtime.
 */
public final class NativeVulkanProbe {
    private static final boolean LOADED;
    private static final String LOAD_ERROR;
    static {
        boolean loaded=false;
        String error="";
        try {
            System.loadLibrary("carx_native_probe");
            loaded=true;
        } catch (Throwable t) {
            error=t.getClass().getSimpleName();
        }
        LOADED=loaded;
        LOAD_ERROR=error;
    }
    private NativeVulkanProbe() {}
    private static native String probeNativeVulkan();
    private static native String probeNativeGpuClear();

    public static JSONObject inspect() {
        JSONObject doc=new JSONObject();
        try {
            doc.put("schema","rm11carx.native-arm64-vulkan-bootstrap.v1");
            doc.put("native_arm64_library_loaded",LOADED);
            doc.put("native_arm64_library_error",LOAD_ERROR);
            doc.put("original_carx_game_code_executed",false);
            doc.put("original_carx_first_frame_rendered",false);
            doc.put("game_engine_runtime_available",false);
            doc.put("purpose","Native Android Vulkan instance and GPU offscreen command test only, NOT PC game execution");
            if (LOADED) {
                JSONObject result=new JSONObject(probeNativeVulkan());
                doc.put("native_runtime",result);
                doc.put("native_arm64_procedure_executed",
                        result.optBoolean("native_arm64_procedure_executed",false));
                doc.put("vulkan_instance_created",
                        result.optBoolean("vulkan_instance_created",false));
                // Execute an independent Vulkan clear/copy on the actual GPU.
                // This is NOT original game execution or an Android game frame.
                try {
                    JSONObject gpu=new JSONObject(probeNativeGpuClear());
                    doc.put("native_gpu_clear_readback",gpu);
                    doc.put("native_gpu_work_verified",
                            gpu.optBoolean("native_gpu_offscreen_clear_and_readback_proven",false));
                } catch (Throwable gpuFailure) {
                    doc.put("native_gpu_work_verified",false);
                    doc.put("gpu_clear_probe_exception",
                            gpuFailure.getClass().getSimpleName());
                }
            } else {
                doc.put("native_arm64_procedure_executed",false);
                doc.put("vulkan_instance_created",false);
                doc.put("native_gpu_work_verified",false);
            }
        } catch (Throwable t) {
            try {
                doc.put("native_probe_exception",t.getClass().getSimpleName());
                doc.put("native_arm64_procedure_executed",false);
                doc.put("vulkan_instance_created",false);
                doc.put("native_gpu_work_verified",false);
            } catch (Exception ignored) {}
        }
        return doc;
    }
}
