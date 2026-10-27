/*
 * RM11 v473. Test only the private Termux/Mesa Vulkan loader and
 * a private Freedreno ICD. Runs as an isolated Android PIE native child.
 * Never hooks system Vulkan, never runs in the Wine or Android UI process.
 * The ICD path comes from a bounded app-private JSON file supplied by Java.
 */
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define EXT_LIMIT 512u
static int has(const VkExtensionProperties *ex,uint32_t n,const char *name){
    for(uint32_t i=0;i<n;i++)
        if(strcmp(ex[i].extensionName,name)==0)return 1;
    return 0;
}
static const char *tf(int yes){return yes?"true":"false";}
int main(void){
    puts("RM11_V473_PROBE=ISOLATED_PRIVATE_VULKAN_CHILD");
    puts("RM11_V473_NO_GPU_SHADERS_OR_SWAPCHAIN=true");
    fflush(stdout);

    void *h=dlopen("librm11_vkloader_v473.so",RTLD_NOW|RTLD_LOCAL);
    printf("RM11_V473_PRIVATE_LOADER=%s\n",h?"LOADED":"DLOPEN_FAILED");
    fflush(stdout);
    if(!h)return 10;

    PFN_vkEnumerateInstanceExtensionProperties enumerate=
        (PFN_vkEnumerateInstanceExtensionProperties)
            dlsym(h,"vkEnumerateInstanceExtensionProperties");
    PFN_vkCreateInstance create=(PFN_vkCreateInstance)
            dlsym(h,"vkCreateInstance");
    if(!enumerate||!create){
        puts("RM11_V473_PROBE_STATUS=INCOMPLETE_LOADER_EXPORTS");
        fflush(stdout);
        dlclose(h);
        return 11;
    }
    uint32_t count=0;
    VkResult r=enumerate(NULL,&count,NULL);
    printf("RM11_V473_EXTENSIONS_QUERY_RESULT=%d\n",(int)r);
    fflush(stdout);
    if(r!=VK_SUCCESS || count>EXT_LIMIT){
        puts("RM11_V473_PROBE_STATUS=EXTENSIONS_FAILED_OR_EXCESS");
        dlclose(h);
        return 12;
    }
    VkExtensionProperties extensions[EXT_LIMIT];
    uint32_t total=count;
    r=enumerate(NULL,&total,extensions);
    if(r!=VK_SUCCESS){
        puts("RM11_V473_PROBE_STATUS=EXTENSIONS_LIST_FAILED");
        dlclose(h);
        return 13;
    }
    int surface=has(extensions,total,"VK_KHR_surface");
    int xcb=has(extensions,total,"VK_KHR_xcb_surface");
    int xlib=has(extensions,total,"VK_KHR_xlib_surface");
    printf("RM11_V473_KHR_SURFACE=%s\n",tf(surface));
    printf("RM11_V473_KHR_XCB_SURFACE=%s\n",tf(xcb));
    printf("RM11_V473_KHR_XLIB_SURFACE=%s\n",tf(xlib));
    fflush(stdout);

    VkApplicationInfo app={0};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="RM11 isolated Vulkan WSI capability test";
    app.apiVersion=VK_API_VERSION_1_1;
    VkInstanceCreateInfo ci={0};
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo=&app;
    VkInstance instance=VK_NULL_HANDLE;
    r=create(&ci,NULL,&instance);
    printf("RM11_V473_CREATE_INSTANCE_RESULT=%d\n",(int)r);
    fflush(stdout);
    if(r!=VK_SUCCESS||instance==VK_NULL_HANDLE){
        puts("RM11_V473_PROBE_STATUS=INSTANCE_CREATE_FAILED");
        dlclose(h);
        return 14;
    }
    PFN_vkEnumeratePhysicalDevices physical=(PFN_vkEnumeratePhysicalDevices)
        dlsym(h,"vkEnumeratePhysicalDevices");
    PFN_vkDestroyInstance destroy=(PFN_vkDestroyInstance)
        dlsym(h,"vkDestroyInstance");
    if(!physical||!destroy){
        puts("RM11_V473_PROBE_STATUS=INSTANCE_DISPATCH_MISSING");
        fflush(stdout);
        dlclose(h);
        return 15;
    }
    uint32_t devices=0;
    r=physical(instance,&devices,NULL);
    printf("RM11_V473_PHYSICAL_ENUM_RESULT=%d\n",(int)r);
    printf("RM11_V473_PHYSICAL_DEVICE_COUNT=%u\n",(unsigned)devices);
    puts("RM11_V473_X11_SURFACE_CREATED=false");
    puts("RM11_V473_SWAPCHAIN_PRESENTED=false");
    puts("RM11_V473_PROBE_STATUS=INSTANCE_AND_DEVICE_QUERY_COMPLETE_WSI_UNVERIFIED");
    fflush(stdout);
    destroy(instance,NULL);
    dlclose(h);
    return 0;
}
