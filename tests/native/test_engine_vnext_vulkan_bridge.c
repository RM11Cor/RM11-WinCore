/* Independent native host policy test: no real GPU or Wine required. */
#include "engine_vnext_wine_vulkan_bridge.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    const char *lib="/data/app/~~package/lib/arm64";
    const char *wine="/data/app/~~package/lib/arm64/libwineprobe.so";
    assert(rm11_vnext_vulkan_policy("libvulkan.so.1",lib,wine,1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so",lib,wine,1));
    assert(!rm11_vnext_vulkan_policy("libGL.so.1",lib,wine,1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",lib,wine,0));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",lib,
           "/data/app/~~package/lib/arm64/libwineserverrm11.so",1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",lib,
           "/data/app/~~package/lib/arm64/librm11_engine_supervisor.so",1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",lib,
           "/data/app/~~package/lib/arm64/libmain_hook.so",1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",
           "/data/app/../../tmp",wine,1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",
           "/data/app//lib/arm64",wine,1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",
           "/data/app/lib/arm64/",wine,1));
    assert(!rm11_vnext_vulkan_policy("libvulkan.so.1",lib,NULL,1));
    assert(!rm11_vnext_vulkan_policy(NULL,lib,wine,1));
    puts("RM11_WINE_CHILD_VULKAN_BRIDGE_HOST_POLICY_PASS cases=12");
    return 0;
}
