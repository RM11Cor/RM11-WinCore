/* RM11 vNext, native Wine child Vulkan loader bridge.
 * Entirely inactive unless explicitly called from a verified child session.
 * No API here claims Android Vulkan enumeration or a rendered frame.
 * SPDX-License-Identifier: MIT
 */
#ifndef RM11_VNEXT_WINE_VULKAN_BRIDGE_H
#define RM11_VNEXT_WINE_VULKAN_BRIDGE_H
#ifdef __cplusplus
extern "C" {
#endif
int rm11_vnext_vulkan_policy(const char *soname, const char *signed_native_dir,
                             const char *process_executable,
                             int manifest_verified);
void *rm11_vnext_open_vulkan(const char *soname, const char *signed_native_dir,
                            int manifest_verified);
#ifdef __cplusplus
}
#endif
#endif
