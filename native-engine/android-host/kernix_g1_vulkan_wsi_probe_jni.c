/* SPDX-License-Identifier: MIT
 * KERNIX G1 real Android native-window Vulkan WSI diagnostic bridge.
 * Reuses pre-existing kernix_swapchain.c as-is. Four queued frame requests,
 * no sustained render loop and no physical display completion assertion.
 * Stage: status=8 is vkCreateSwapchainKHR failure; Vulkan VkResult retained.
 */
#include <jni.h>
#include <stdint.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error G1 WSI diagnostic runs only on Android ARM64
#endif

struct kernix_swapchain_report_v1 {
  uint32_t struct_size, status, width, height, images, format;
  uint32_t present_mode, queue_family, vk_error_code, frame_presented;
  uint32_t frames_attempted, frames_completed;
};
extern uint32_t kernix_swapchain_probe_v1(
    ANativeWindow*,struct kernix_swapchain_report_v1*);

/* The exact 12-word layout is a stable app-local JNI/Java protocol.
 * Every error returns status and VkResult; all stages fail closed. */
JNIEXPORT jintArray JNICALL
Java_org_kernix_g1vulkanprobe_MainActivity_nativeProbe(
    JNIEnv* env, jclass ignored, jobject surface) {
  (void)ignored;
  struct kernix_swapchain_report_v1 out={0};
  out.struct_size=(uint32_t)sizeof(out);
  out.status=1u;
  out.queue_family=UINT32_MAX;
  if (surface) {
    ANativeWindow* window=ANativeWindow_fromSurface(env,surface);
    if (window) {
      (void)kernix_swapchain_probe_v1(window,&out);
      ANativeWindow_release(window);
    }
  }
  const jint values[12]={
    (jint)out.struct_size,
    (jint)out.status,
    (jint)out.width,
    (jint)out.height,
    (jint)out.images,
    (jint)out.format,
    (jint)out.present_mode,
    (jint)out.queue_family,
    (jint)(int32_t)out.vk_error_code,
    (jint)out.frame_presented,
    (jint)out.frames_attempted,
    (jint)out.frames_completed
  };
  jintArray result=(*env)->NewIntArray(env,12);
  if (!result)return NULL;
  (*env)->SetIntArrayRegion(env,result,0,12,values);
  return result;
}
