#include <jni.h>
#include <stdint.h>

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
