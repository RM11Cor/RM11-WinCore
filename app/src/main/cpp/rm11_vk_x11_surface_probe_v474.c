/*
 * RM11 v474: surface creation smoke test with the private Termux/Mesa loader
 * and ICD, on the live native Lorie :2 X11 server. Dedicated ARM64 child,
 * not in UI, game or Wine. No swapchain, shader, game file modifications.
 *
 * Xlib signatures are loaded dynamically because the Android NDK has no
 * desktop Xlib headers. Vulkan's Xlib surface create info ABI is defined
 * by VK_KHR_xlib_surface and uses LP64 Display*/Window layouts on AArch64.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#define MAX_EXT 512u
#define MAX_GPUS 8u
#define MAX_QF 32u

typedef struct {
    VkStructureType sType;
    const void *pNext;
    VkFlags flags;
    void *dpy;
    unsigned long window;
} RM11XlibSurfaceCreateInfo;

typedef VkResult (VKAPI_PTR *RM11CreateXlibSurface)(
    VkInstance,const RM11XlibSurfaceCreateInfo *,
    const VkAllocationCallbacks *, VkSurfaceKHR *);

typedef void *(*RM11XOpenDisplay)(const char *);
typedef unsigned long (*RM11XDefaultRootWindow)(void *);
typedef unsigned long (*RM11XCreateSimpleWindow)(
    void *,unsigned long,int,int,unsigned int,unsigned int,
    unsigned int,unsigned long,unsigned long);
typedef int (*RM11XMapWindow)(void *,unsigned long);
typedef int (*RM11XFlush)(void *);
typedef int (*RM11XDestroyWindow)(void *,unsigned long);
typedef int (*RM11XCloseDisplay)(void *);

static void stamp(const char *key,const char *value){
    printf("RM11_V474_%s=%s\n",key,value);
    fflush(stdout);
}
static void number(const char *key,int value){
    printf("RM11_V474_%s=%d\n",key,value);
    fflush(stdout);
}
static int supported(const VkExtensionProperties *a,uint32_t n,const char *x){
    for(uint32_t i=0;i<n;i++)
        if(strcmp(a[i].extensionName,x)==0)return 1;
    return 0;
}
int main(void){
    stamp("PROBE","ISOLATED_PRIVATE_X11_XLIB_SURFACE_CHILD");
    stamp("WINE_GAME_PROCESS","NOT_STARTED");
    stamp("SWAPCHAIN_PRESENT","NOT_ATTEMPTED");
    stamp("X11_SERVER","127.0.0.1:2");
    void *lib=dlopen("libX11.so",RTLD_NOW|RTLD_LOCAL);
    if(!lib){
        stamp("XLIB_CLIENT","DLOPEN_FAILED");
        return 10;
    }
    RM11XOpenDisplay openDisplay=(RM11XOpenDisplay)dlsym(lib,"XOpenDisplay");
    RM11XDefaultRootWindow root=(RM11XDefaultRootWindow)dlsym(lib,"XDefaultRootWindow");
    RM11XCreateSimpleWindow createWindow=(RM11XCreateSimpleWindow)dlsym(lib,"XCreateSimpleWindow");
    RM11XMapWindow mapWindow=(RM11XMapWindow)dlsym(lib,"XMapWindow");
    RM11XFlush flush=(RM11XFlush)dlsym(lib,"XFlush");
    RM11XDestroyWindow destroyWindow=(RM11XDestroyWindow)dlsym(lib,"XDestroyWindow");
    RM11XCloseDisplay closeDisplay=(RM11XCloseDisplay)dlsym(lib,"XCloseDisplay");
    if(!openDisplay||!root||!createWindow||!mapWindow||!flush
       ||!destroyWindow||!closeDisplay){
        stamp("XLIB_CLIENT","SYMBOLS_MISSING");
        dlclose(lib);
        return 11;
    }
    void *display=openDisplay("127.0.0.1:2");
    if(!display){
        stamp("XLIB_DISPLAY","CONNECT_FAILED");
        dlclose(lib);
        return 12;
    }
    stamp("XLIB_DISPLAY","CONNECTED");
    unsigned long win=createWindow(display,root(display),32,32,360,220,0,0,0);
    if(!win){
        stamp("XLIB_WINDOW","CREATE_FAILED");
        closeDisplay(display);
        dlclose(lib);
        return 13;
    }
    mapWindow(display,win);
    flush(display);
    stamp("XLIB_WINDOW","MAPPED_REQUESTED");

    int result=0;
    VkInstance instance=VK_NULL_HANDLE;
    VkSurfaceKHR surface=VK_NULL_HANDLE;
    void *vk=dlopen("librm11_vkloader_v473.so",RTLD_NOW|RTLD_LOCAL);
    if(!vk){
        stamp("PRIVATE_VULKAN_LOADER","DLOPEN_FAILED");
        result=14;goto done;
    }
    PFN_vkGetInstanceProcAddr gip=(PFN_vkGetInstanceProcAddr)
        dlsym(vk,"vkGetInstanceProcAddr");
    PFN_vkCreateInstance createInstance=(PFN_vkCreateInstance)
        dlsym(vk,"vkCreateInstance");
    PFN_vkEnumerateInstanceExtensionProperties extensions=
        (PFN_vkEnumerateInstanceExtensionProperties)
        dlsym(vk,"vkEnumerateInstanceExtensionProperties");
    if(!gip||!createInstance||!extensions){
        stamp("PRIVATE_VULKAN_LOADER","MISSING_EXPORTS");
        result=15;goto done;
    }
    uint32_t ec=0;
    VkResult v=extensions(NULL,&ec,NULL);
    if(v!=VK_SUCCESS || ec>MAX_EXT){
        stamp("VK_INSTANCE_EXTENSIONS","BAD_COUNT_OR_QUERY");
        result=16;goto done;
    }
    VkExtensionProperties props[MAX_EXT];
    v=extensions(NULL,&ec,props);
    if(v!=VK_SUCCESS || !supported(props,ec,"VK_KHR_surface")
      || !supported(props,ec,"VK_KHR_xlib_surface")){
        stamp("VK_XLIB_SURFACE_EXTENSION","NOT_AVAILABLE");
        result=17;goto done;
    }
    stamp("VK_XLIB_SURFACE_EXTENSION","AVAILABLE");
    const char *needed[]={"VK_KHR_surface","VK_KHR_xlib_surface"};
    VkApplicationInfo app={0};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="RM11 X11 surface test";
    app.apiVersion=VK_API_VERSION_1_1;
    VkInstanceCreateInfo info={0};
    info.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    info.pApplicationInfo=&app;
    info.enabledExtensionCount=2;
    info.ppEnabledExtensionNames=needed;
    v=createInstance(&info,NULL,&instance);
    number("VK_CREATE_INSTANCE_RESULT",(int)v);
    if(v!=VK_SUCCESS || instance==VK_NULL_HANDLE){
        result=18;goto done;
    }
    RM11CreateXlibSurface createSurface=(RM11CreateXlibSurface)
        gip(instance,"vkCreateXlibSurfaceKHR");
    PFN_vkDestroySurfaceKHR destroySurface=(PFN_vkDestroySurfaceKHR)
        gip(instance,"vkDestroySurfaceKHR");
    PFN_vkDestroyInstance destroyInstance=(PFN_vkDestroyInstance)
        gip(instance,"vkDestroyInstance");
    PFN_vkEnumeratePhysicalDevices physical=(PFN_vkEnumeratePhysicalDevices)
        gip(instance,"vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceQueueFamilyProperties queues=
        (PFN_vkGetPhysicalDeviceQueueFamilyProperties)
        gip(instance,"vkGetPhysicalDeviceQueueFamilyProperties");
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR supports=(PFN_vkGetPhysicalDeviceSurfaceSupportKHR)
        gip(instance,"vkGetPhysicalDeviceSurfaceSupportKHR");
    PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR capabilities=
        (PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR)
        gip(instance,"vkGetPhysicalDeviceSurfaceCapabilitiesKHR");
    if(!createSurface||!destroySurface||!destroyInstance||!physical
       ||!queues||!supports||!capabilities){
        stamp("VK_XLIB_SURFACE_DISPATCH","MISSING");
        result=19;goto clean_instance;
    }
    RM11XlibSurfaceCreateInfo xi={0};
    xi.sType=(VkStructureType)1000004000; /* VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR */
    xi.dpy=display;
    xi.window=win;
    v=createSurface(instance,&xi,NULL,&surface);
    number("VK_CREATE_XLIB_SURFACE_RESULT",(int)v);
    fflush(stdout);
    if(v!=VK_SUCCESS || surface==VK_NULL_HANDLE){
        result=20;goto clean_instance;
    }
    stamp("X11_VULKAN_SURFACE","CREATED");
    uint32_t nc=0;
    v=physical(instance,&nc,NULL);
    number("PHYSICAL_ENUM_RESULT",(int)v);
    number("PHYSICAL_DEVICE_COUNT",(int)nc);
    if(v!=VK_SUCCESS || nc==0 || nc>MAX_GPUS){
        result=21;goto clean_instance;
    }
    VkPhysicalDevice gpus[MAX_GPUS];
    v=physical(instance,&nc,gpus);
    if(v!=VK_SUCCESS){
        result=22;goto clean_instance;
    }
    int supportsPresent=0;
    for(uint32_t i=0;i<nc;i++){
        uint32_t qn=0;
        queues(gpus[i],&qn,NULL);
        if(qn>MAX_QF){
            stamp("QUEUE_FAMILY_COUNT","OVER_LIMIT");
            continue;
        }
        VkQueueFamilyProperties qp[MAX_QF];
        queues(gpus[i],&qn,qp);
        for(uint32_t q=0;q<qn;q++){
            VkBool32 yes=VK_FALSE;
            v=supports(gpus[i],q,surface,&yes);
            if(v==VK_SUCCESS && yes==VK_TRUE){
                supportsPresent=1;
                printf("RM11_V474_PRESENT_QUEUE_FAMILY=%u\n",q);
                break;
            }
        }
        if(supportsPresent){
            VkSurfaceCapabilitiesKHR caps;
            v=capabilities(gpus[i],surface,&caps);
            number("VK_SURFACE_CAPABILITIES_RESULT",(int)v);
            break;
        }
    }
    stamp("X11_SURFACE_PRESENT_QUEUE",supportsPresent?"SUPPORTED":"UNAVAILABLE");
    stamp("SWAPCHAIN_PRESENT","NOT_ATTEMPTED");
    if(!supportsPresent) result=23;
clean_instance:
    if(surface!=VK_NULL_HANDLE && destroySurface)destroySurface(instance,surface,NULL);
    if(instance!=VK_NULL_HANDLE && destroyInstance)destroyInstance(instance,NULL);
done:
    if(vk)dlclose(vk);
    destroyWindow(display,win);
    flush(display);
    closeDisplay(display);
    dlclose(lib);
    number("PROCESS_COMPLETED",(int)result);
    return result;
}
