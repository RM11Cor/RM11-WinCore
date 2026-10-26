#include <assert.h>
#include "wine_vulkan_bridge_policy_v458.h"
int main(void) {
    assert(rm11_v458_should_retry_android_vulkan("libvulkan.so.1","1",1,1));
    assert(!rm11_v458_should_retry_android_vulkan("libvulkan.so","1",1,1));
    assert(!rm11_v458_should_retry_android_vulkan("libGL.so.1","1",1,1));
    assert(!rm11_v458_should_retry_android_vulkan("libvulkan.so.1","0",1,1));
    assert(!rm11_v458_should_retry_android_vulkan("libvulkan.so.1","1",0,1));
    assert(!rm11_v458_should_retry_android_vulkan("libvulkan.so.1","1",1,0));
    assert(!rm11_v458_should_retry_android_vulkan(0,"1",1,1));
    return 0;
}
