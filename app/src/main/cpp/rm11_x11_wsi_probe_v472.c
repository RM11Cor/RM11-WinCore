/*
 * RM11 v472 - independently executed, native Bionic Vulkan/X11 WSI probe.
 * Built as an Android PIE placed inside signed APK nativeLibraryDir.
 * No game, display surface, shader, Wine/FEX state, disk writes or driver changes.
 * Its own process can crash without bringing down the Java app.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vulkan/vulkan.h>

#define MAX_EXTENSIONS 512u

static int has_name(const VkExtensionProperties *exts,uint32_t count,
                    const char *name){
    for(uint32_t i=0;i<count;i++)
        if(!strcmp(exts[i].extensionName,name))return 1;
    return 0;
}
static const char *yn(int v){return v?"true":"false";}
int main(void){
    /* Emit context BEFORE loading the driver so aborts are identifiable. */
    puts("RM11_V472_CHILD_PROBE_VERSION=1");
    puts("RM11_V472_WSI_PROBE_PROCESS=ISOLATED_NATIVE_CHILD");
    puts("RM11_V472_NO_SURFACE_OR_SHADER_SUBMISSION=true");
    fflush(stdout);

    void *vulkan=dlopen("libvulkan.so",RTLD_NOW|RTLD_LOCAL);
    printf("RM11_V472_ANDROID_VULKAN_LOADER_DLOPEN=%s\n",
           vulkan?"SUCCESS":"FAILED");
    fflush(stdout);

    void *desktopGL=dlopen("libGL.so.1",RTLD_NOW|RTLD_LOCAL);
    printf("RM11_V472_LINUX_DESKTOP_GL_SONAME_DLOPEN=%s\n",
           desktopGL?"SUCCESS":"FAILED");
    fflush(stdout);
    if(desktopGL)dlclose(desktopGL);
    if(!vulkan){
        puts("RM11_V472_X11_VULKAN_WSI=LOADER_UNAVAILABLE");
        return 10;
    }

    PFN_vkEnumerateInstanceExtensionProperties enumerate=
        (PFN_vkEnumerateInstanceExtensionProperties)
        dlsym(vulkan,"vkEnumerateInstanceExtensionProperties");
    if(!enumerate){
        puts("RM11_V472_X11_VULKAN_WSI=EXTENSION_QUERY_UNAVAILABLE");
        dlclose(vulkan);
        return 11;
    }
    uint32_t count=0;
    VkResult res=enumerate(NULL,&count,NULL);
    printf("RM11_V472_INSTANCE_EXTENSION_COUNT=%u\n",(unsigned)count);
    printf("RM11_V472_INSTANCE_EXTENSION_COUNT_RESULT=%d\n",(int)res);
    fflush(stdout);
    if(res!=VK_SUCCESS){
        puts("RM11_V472_X11_VULKAN_WSI=ENUMERATION_FAILED");
        dlclose(vulkan);
        return 12;
    }
    if(count>MAX_EXTENSIONS){
        puts("RM11_V472_X11_VULKAN_WSI=TRUNCATED_UNVERIFIED");
        dlclose(vulkan);
        return 13;
    }
    VkExtensionProperties exts[MAX_EXTENSIONS];
    uint32_t got=count;
    res=enumerate(NULL,&got,exts);
    printf("RM11_V472_INSTANCE_EXTENSIONS_QUERY_RESULT=%d\n",(int)res);
    fflush(stdout);
    if(res!=VK_SUCCESS){
        puts("RM11_V472_X11_VULKAN_WSI=ENUMERATION_INCOMPLETE");
        dlclose(vulkan);
        return 14;
    }

    int surface=has_name(exts,got,"VK_KHR_surface");
    int xcb=has_name(exts,got,"VK_KHR_xcb_surface");
    int xlib=has_name(exts,got,"VK_KHR_xlib_surface");
    int android=has_name(exts,got,"VK_KHR_android_surface");
    printf("RM11_V472_KHR_SURFACE=%s\n",yn(surface));
    printf("RM11_V472_KHR_XCB_SURFACE=%s\n",yn(xcb));
    printf("RM11_V472_KHR_XLIB_SURFACE=%s\n",yn(xlib));
    printf("RM11_V472_KHR_ANDROID_SURFACE=%s\n",yn(android));
    /* No X11 surface/presentation was created. Even extension availability
     * is merely a precondition, never proof of a working swapchain. */
    printf("RM11_V472_X11_VULKAN_WSI=%s\n",
           surface&&(xcb||xlib)
               ?"INSTANCE_EXTENSIONS_PRESENT_SURFACE_UNVERIFIED"
               :"INSTANCE_EXTENSIONS_ABSENT");
    puts("RM11_V472_X11_SWAPCHAIN_PRESENTED=UNVERIFIED");
    fflush(stdout);
    dlclose(vulkan);
    return 0;
}
