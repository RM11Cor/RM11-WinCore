#ifndef RM11_PRIVATE_VULKAN_WSI_POLICY_V479_H
#define RM11_PRIVATE_VULKAN_WSI_POLICY_V479_H
#include <string.h>
/* Only the exact Wine Linux Vulkan SONAME from a signed Wine launcher
 * can enter the game-only private Mesa experiment. */
static inline int rm11_v479_private_vulkan_match(const char *requested,
        const char *flag, int signed_wine_launcher) {
    return requested && !strcmp(requested,"libvulkan.so.1")
        && flag && !strcmp(flag,"1") && signed_wine_launcher;
}
#endif
