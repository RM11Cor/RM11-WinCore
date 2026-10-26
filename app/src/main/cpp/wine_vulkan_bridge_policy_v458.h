#ifndef RM11_WINE_VULKAN_BRIDGE_POLICY_V458_H
#define RM11_WINE_VULKAN_BRIDGE_POLICY_V458_H
#include <string.h>
/* Exact Bionic Vulkan compatibility retry. Never map generic .so names. */
static inline int rm11_v458_should_retry_android_vulkan(
        const char *requested, const char *flag,
        int signed_wine_launcher, int original_dlopen_failed) {
    return requested && !strcmp(requested,"libvulkan.so.1")
        && flag && !strcmp(flag,"1") && signed_wine_launcher
        && original_dlopen_failed;
}
#endif
