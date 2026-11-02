#include <jni.h>
#include <stdint.h>
#include <stdio.h>

/* Bridge to original KERNIX Android host; ABI versioned native structure. */
struct kernix_host_info_v1 {
    uint32_t struct_size;
    uint32_t api_version;
    uint32_t capabilities;
    uint32_t vulkan_instance_api_version;
};
extern uint32_t kernix_host_probe_v1(struct kernix_host_info_v1 *);
extern uint32_t kernix_host_abi_version(void);

/*
 * The app explicitly loads libkernix_host.so and this JNI shim in order;
 * no auto-detection or arbitrary native code is executed.
 */
JNIEXPORT jintArray JNICALL
Java_org_kernix_host_MainActivity_nativeHostProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    struct kernix_host_info_v1 info = {
        .struct_size = (uint32_t)sizeof(struct kernix_host_info_v1),
        .api_version = 0,
        .capabilities = 0,
        .vulkan_instance_api_version = 0
    };
    uint32_t bits = kernix_host_probe_v1(&info);
    jint result[5] = {
        (jint)kernix_host_abi_version(),
        (jint)info.api_version,
        (jint)bits,
        (jint)info.vulkan_instance_api_version,
        (jint)info.struct_size,
    };
    jintArray out = (*env)->NewIntArray(env, 5);
    if (out == NULL) return NULL;
    (*env)->SetIntArrayRegion(env, out, 0, 5, result);
    return out;
}

/* Return GPU survey as a bounded string; the Java app does not assume success. */
struct kernix_gpu_report_v1 {
    uint32_t struct_size;
    uint32_t status;
    uint32_t device_count;
    uint32_t vendor_id;
    uint32_t device_id;
    uint32_t api_version;
    char device_name[256];
};
extern uint32_t kernix_gpu_probe_v1(struct kernix_gpu_report_v1 *);
JNIEXPORT jstring JNICALL
Java_org_kernix_host_MainActivity_nativeGpuProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    struct kernix_gpu_report_v1 report = {0};
    report.struct_size = (uint32_t)sizeof(report);
    uint32_t status = kernix_gpu_probe_v1(&report);
    char output[512];
    if (status == 1u) {
        unsigned maj = report.api_version >> 22;
        unsigned min = (report.api_version >> 12) & 0x3ffu;
        unsigned pat = report.api_version & 0xfffu;
        (void)snprintf(output, sizeof(output),
          "Physical Vulkan devices: %u\\nGPU: %.255s\\nVendor: 0x%04x\\nDevice: 0x%04x\\nVulkan device API: %u.%u.%u\\nSwapchain: NOT TESTED\\nGames: NOT TESTED",
          report.device_count,report.device_name,report.vendor_id,report.device_id,maj,min,pat);
    } else {
        (void)snprintf(output,sizeof(output),
          "GPU probe status: %u\\nNo device capability claim; rendering and games NOT TESTED",status);
    }
    return (*env)->NewStringUTF(env,output);
}


/* Native Android window -> genuine Vulkan surface / present queue bootstrap. */
#include <android/native_window_jni.h>
struct kernix_surface_report_v1 {
    uint32_t struct_size;
    uint32_t status;
    uint32_t device_count;
    uint32_t queue_family_index;
    uint32_t gpu_api_version;
    uint32_t window_width;
    uint32_t window_height;
    uint32_t vk_error_code;
};
extern uint32_t kernix_surface_probe_v1(ANativeWindow *,
                                          struct kernix_surface_report_v1 *);
JNIEXPORT jstring JNICALL
Java_org_kernix_host_MainActivity_nativeSurfaceProbe(JNIEnv *env, jclass clazz,
                                                        jobject surface) {
    (void)clazz;
    if (!surface) return (*env)->NewStringUTF(env, "Android Surface: missing");
    ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
    if (!window) return (*env)->NewStringUTF(env, "Native window: unavailable");
    struct kernix_surface_report_v1 report = {0};
    report.struct_size = sizeof(report);
    uint32_t status = kernix_surface_probe_v1(window, &report);
    ANativeWindow_release(window);
    char output[512];
    if (status == 0u) {
        (void)snprintf(output, sizeof(output),
          "Real Android Vulkan surface: CREATED and destroyed safely\n"
          "GPU devices: %u\nGraphics/present queue family: %u\n"
          "Native window: %u x %u\nSwapchain: NOT CREATED\nFrame: NOT RENDERED\nWindows game: NOT TESTED",
          report.device_count, report.queue_family_index,
          report.window_width, report.window_height);
    } else {
        (void)snprintf(output, sizeof(output),
          "Android Vulkan surface NOT READY\nStage status: %u\n"
          "VkResult: %d\nWindow: %u x %u\n"
          "No game or swapchain claim",status, (int32_t)report.vk_error_code,
          report.window_width,report.window_height);
    }
    return (*env)->NewStringUTF(env, output);
}


/* Genuine temporary Vulkan swapchain construction; no frames presented. */
struct kernix_swapchain_report_v1 {
    uint32_t struct_size, status, width, height, images, format;
    uint32_t present_mode, queue_family, vk_error_code;
};
extern uint32_t kernix_swapchain_probe_v1(
    ANativeWindow *, struct kernix_swapchain_report_v1 *);
JNIEXPORT jstring JNICALL
Java_org_kernix_host_MainActivity_nativeSwapchainProbe(
    JNIEnv *env, jclass clazz, jobject surface) {
    (void)clazz;
    if (!surface) return (*env)->NewStringUTF(env,"Swapchain: no Android Surface");
    ANativeWindow *window=ANativeWindow_fromSurface(env,surface);
    if (!window) return (*env)->NewStringUTF(env,"Swapchain: no native window");
    struct kernix_swapchain_report_v1 report={0};
    report.struct_size=sizeof(report);
    uint32_t status=kernix_swapchain_probe_v1(window,&report);
    ANativeWindow_release(window);
    char output[512];
    if (status==0u) {
        (void)snprintf(output,sizeof(output),
          "Temporary VkSwapchainKHR: CREATED and destroyed\n"
          "Extent: %u x %u\nRequested images: %u\n"
          "Vulkan format: %u\nGraphics/present queue: %u\n"
          "Frame acquired/presented: NO\nWine/game runtime: NOT INTEGRATED",
          report.width,report.height,report.images,report.format,report.queue_family);
    } else {
        (void)snprintf(output,sizeof(output),
          "VkSwapchainKHR: NOT READY\nStage: %u\nVkResult: %d\n"
          "No gameplay or frame-presentation claim",
          status,(int32_t)report.vk_error_code);
    }
    return (*env)->NewStringUTF(env,output);
}
