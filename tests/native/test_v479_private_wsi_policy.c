#include <assert.h>
#include <stdio.h>
#include "wine_private_vulkan_wsi_policy_v479.h"
int main(void) {
    assert(rm11_v479_private_vulkan_match("libvulkan.so.1","1",1));
    assert(!rm11_v479_private_vulkan_match("libvulkan.so","1",1));
    assert(!rm11_v479_private_vulkan_match("libGL.so.1","1",1));
    assert(!rm11_v479_private_vulkan_match("/tmp/libvulkan.so.1","1",1));
    assert(!rm11_v479_private_vulkan_match("libvulkan.so.1","0",1));
    assert(!rm11_v479_private_vulkan_match("libvulkan.so.1","1",0));
    assert(!rm11_v479_private_vulkan_match("libvulkan.so.1",NULL,1));
    assert(!rm11_v479_private_vulkan_match(NULL,"1",1));
    puts("RM11_V479_SCOPED_PRIVATE_VULKAN_POLICY_PASSED");
    return 0;
}
