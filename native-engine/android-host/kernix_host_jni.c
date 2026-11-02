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
