/* v49093: isolated signed app-private Vulkan *loader* probe.
 * Unlike direct ICD GPA calls this enters the Termux Bionic desktop loader
 * which owns the X11 WSI instance extensions. Never use Android system Vulkan
 * or change game files. No X11 surface/Swapchain/present is claimed.
 */
#define _POSIX_C_SOURCE 200809L
#include <jni.h>
#include <dlfcn.h>
#include <vulkan/vulkan.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool safe_file(const char *path,const char *suffix,const char *prefix){
    if(!path||strncmp(path,prefix,strlen(prefix))!=0 || strlen(path)>2048
       ||strstr(path,"/../")||strstr(path,"//"))return false;
    size_t length=strlen(path),end=strlen(suffix);
    return length>end && strcmp(path+length-end,suffix)==0;
}
static bool present(const VkExtensionProperties *props,uint32_t n,const char *name){
    for(uint32_t i=0;i<n;i++)
        if(strcmp(props[i].extensionName,name)==0)return true;
    return false;
}
static const char *yn(bool b){return b?"true":"false";}
JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RM11PrivateX11LoaderProbe_nativeProbe(
        JNIEnv *env,jclass cls,jstring loaderPath,jstring jsonPath){
    (void)cls;
    const char *stage="START",*loader=NULL,*json=NULL;
    void *handle=NULL,*symbol=NULL;
    PFN_vkEnumerateInstanceExtensionProperties enumerate=NULL;
    PFN_vkCreateInstance create=NULL;
    PFN_vkDestroyInstance destroy=NULL;
    PFN_vkEnumeratePhysicalDevices physicals=NULL;
    VkResult extensionResult=VK_NOT_READY,instanceResult=VK_NOT_READY;
    VkResult physicalResult=VK_NOT_READY;
    VkInstance instance=VK_NULL_HANDLE;
    uint32_t count=0,physicalCount=0;
    bool surface=false,xlib=false,xcb=false,android=false,instanceCreated=false;
    bool loaderOpened=false;
    char report[1150];
    if(!loaderPath||!jsonPath){stage="PATH_ARGUMENTS_MISSING";goto done;}
    loader=(*env)->GetStringUTFChars(env,loaderPath,NULL);
    json=(*env)->GetStringUTFChars(env,jsonPath,NULL);
    if(!loader||!json){stage="JNI_PATH_DECODE_FAILED";goto done;}
    stage="VALIDATE_SIGNED_PRIVATE_PATHS";
    if(!safe_file(loader,"/librm11_vkloader_v473.so","/data/app/")
       ||!safe_file(json,"/v49028-mini-desktop-vulkan.json","/data/")){
        stage="PRIVATE_LOADER_PATH_NOT_TRUSTED";goto done;
    }
    /* This probe runs in the dedicated :rm11_graphics_probe process only. */
    stage="PRIVATE_ICD_JSON_ENV";
    if(setenv("VK_DRIVER_FILES",json,1)!=0
       ||setenv("VK_ICD_FILENAMES",json,1)!=0){
        stage="PRIVATE_ICD_JSON_SETENV_FAILED";goto done;
    }
    stage="PRIVATE_DESKTOP_LOADER_DLOPEN";
    handle=dlopen(loader,RTLD_NOW|RTLD_LOCAL);
    if(!handle){stage="PRIVATE_DESKTOP_LOADER_DLOPEN_FAILED";goto done;}
    loaderOpened=true;
#define LOAD(name,symbolName) do { \
    symbol=dlsym(handle,symbolName); \
    if(sizeof(name)!=sizeof(symbol)||!symbol){stage="PRIVATE_LOADER_REQUIRED_EXPORT_MISSING";goto done;} \
    memcpy(&(name),&symbol,sizeof(name)); \
} while(0)
    LOAD(enumerate,"vkEnumerateInstanceExtensionProperties");
    LOAD(create,"vkCreateInstance");
    LOAD(destroy,"vkDestroyInstance");
    LOAD(physicals,"vkEnumeratePhysicalDevices");
    stage="PRIVATE_DESKTOP_LOADER_ENUM_INSTANCE_EXTENSIONS";
    extensionResult=enumerate(NULL,&count,NULL);
    if(extensionResult!=VK_SUCCESS||!count||count>256){
        stage="PRIVATE_DESKTOP_LOADER_EXTENSION_COUNT_FAILED";goto done;
    }
    VkExtensionProperties extensions[256];
    extensionResult=enumerate(NULL,&count,extensions);
    if(extensionResult!=VK_SUCCESS||count>256){
        stage="PRIVATE_DESKTOP_LOADER_EXTENSION_LIST_FAILED";goto done;
    }
    surface=present(extensions,count,"VK_KHR_surface");
    xlib=present(extensions,count,"VK_KHR_xlib_surface");
    xcb=present(extensions,count,"VK_KHR_xcb_surface");
    android=present(extensions,count,"VK_KHR_android_surface");
    if(!surface||(!xlib&&!xcb)){
        stage="PRIVATE_DESKTOP_LOADER_X11_WSI_EXTENSIONS_UNAVAILABLE";goto done;
    }
    stage="PRIVATE_DESKTOP_LOADER_CREATE_INSTANCE";
    VkApplicationInfo ai={
        .sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName="KERNIX v49093 X11 loader diagnostics",
        .apiVersion=VK_API_VERSION_1_0
    };
    const char *enabled[]={VK_KHR_SURFACE_EXTENSION_NAME,
                           xcb?"VK_KHR_xcb_surface":"VK_KHR_xlib_surface"};
    VkInstanceCreateInfo ci={
        .sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo=&ai,
        .enabledExtensionCount=2,
        .ppEnabledExtensionNames=enabled
    };
    instanceResult=create(&ci,NULL,&instance);
    if(instanceResult!=VK_SUCCESS||instance==VK_NULL_HANDLE){
        stage="PRIVATE_DESKTOP_LOADER_CREATE_INSTANCE_FAILED";goto done;
    }
    instanceCreated=true;
    stage="PRIVATE_DESKTOP_LOADER_ENUM_PHYSICAL_DEVICES";
    physicalResult=physicals(instance,&physicalCount,NULL);
    if(physicalResult!=VK_SUCCESS||physicalCount==0){
        stage="PRIVATE_DESKTOP_LOADER_PHYSICAL_DEVICE_UNAVAILABLE";goto done;
    }
    stage="PRIVATE_DESKTOP_X11_LOADER_READY_SURFACE_AND_PRESENT_UNPROVEN";
done:
    if(instance!=VK_NULL_HANDLE&&destroy)destroy(instance,NULL);
    if(handle)dlclose(handle);
    if(json)(*env)->ReleaseStringUTFChars(env,jsonPath,json);
    if(loader)(*env)->ReleaseStringUTFChars(env,loaderPath,loader);
    snprintf(report,sizeof(report),
        "{\"schema\":\"kernix.private-x11-loader.v49093\","
        "\"stage\":\"%s\",\"loaderOpened\":%s,"
        "\"extensionResult\":%d,\"instanceResult\":%d,"
        "\"physicalResult\":%d,\"physicalCount\":%u,"
        "\"khrSurface\":%s,\"xlibSurface\":%s,\"xcbSurface\":%s,"
        "\"androidSurface\":%s,\"instanceCreated\":%s,"
        "\"actualX11SurfaceCreated\":false,"
        "\"swapchainPresented\":false,\"wineD3dFrameProven\":false,"
        "\"realGameFrameProven\":false}",
        stage,yn(loaderOpened),(int)extensionResult,(int)instanceResult,
        (int)physicalResult,physicalCount,yn(surface),yn(xlib),yn(xcb),
        yn(android),yn(instanceCreated));
    return (*env)->NewStringUTF(env,report);
#undef LOAD
}
