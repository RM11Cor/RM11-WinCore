/*
 * RM11 v475: clear-color swapchain/presentation smoke test with the private Termux/Mesa loader
 * and ICD, on the live native Lorie :2 X11 server. Dedicated ARM64 child,
 * not in UI, game or Wine. No swapchain, shader, game file modifications.
 *
 * Xlib signatures are loaded dynamically because the Android NDK has no
 * desktop Xlib headers. Vulkan's Xlib surface create info ABI is defined
 * by VK_KHR_xlib_surface and uses LP64 Xlib display pointer and window ID on AArch64.
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

/*
 * This is the first *actual* Vulkan Xlib presentation test.  Render a bright
 * static clear-color image without a shader or any game's assets, then leave
 * it on screen briefly for Android/X11 capture. Every failure is named.
 */
static int rm11_present_frame(VkInstance instance,VkPhysicalDevice gpu,
                             VkSurfaceKHR surface,uint32_t family,
                             PFN_vkGetInstanceProcAddr gip) {
    VkDevice device=VK_NULL_HANDLE;
    VkSwapchainKHR swapchain=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    VkSemaphore acquired=VK_NULL_HANDLE,rendered=VK_NULL_HANDLE;
    VkResult v;
    int outcome=1;
    PFN_vkGetDeviceProcAddr getDevice=(PFN_vkGetDeviceProcAddr)
        gip(instance,"vkGetDeviceProcAddr");
    PFN_vkCreateDevice createDevice=(PFN_vkCreateDevice)
        gip(instance,"vkCreateDevice");
    PFN_vkEnumerateDeviceExtensionProperties devExt=
        (PFN_vkEnumerateDeviceExtensionProperties)
        gip(instance,"vkEnumerateDeviceExtensionProperties");
    PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR getCaps=
        (PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR)
        gip(instance,"vkGetPhysicalDeviceSurfaceCapabilitiesKHR");
    PFN_vkGetPhysicalDeviceSurfaceFormatsKHR getFormats=
        (PFN_vkGetPhysicalDeviceSurfaceFormatsKHR)
        gip(instance,"vkGetPhysicalDeviceSurfaceFormatsKHR");
    PFN_vkGetPhysicalDeviceSurfacePresentModesKHR getModes=
        (PFN_vkGetPhysicalDeviceSurfacePresentModesKHR)
        gip(instance,"vkGetPhysicalDeviceSurfacePresentModesKHR");
    if(!getDevice||!createDevice||!devExt||!getCaps||!getFormats||!getModes){
        stamp("PRESENT_STATUS","MISSING_INSTANCE_DISPATCH");
        return 1;
    }
    uint32_t extensions=0;
    v=devExt(gpu,NULL,&extensions,NULL);
    if(v!=VK_SUCCESS || extensions>MAX_EXT) {
        stamp("PRESENT_STATUS","DEVICE_EXTENSION_ENUM_FAILED");
        return 2;
    }
    VkExtensionProperties supportedExt[MAX_EXT];
    v=devExt(gpu,NULL,&extensions,supportedExt);
    if(v!=VK_SUCCESS || !supported(supportedExt,extensions,VK_KHR_SWAPCHAIN_EXTENSION_NAME)){
        stamp("PRESENT_STATUS","VK_KHR_SWAPCHAIN_NOT_SUPPORTED");
        return 3;
    }
    stamp("VK_KHR_SWAPCHAIN","SUPPORTED");
    VkSurfaceCapabilitiesKHR caps;
    v=getCaps(gpu,surface,&caps);
    number("SURFACE_CAPABILITIES_RESULT",(int)v);
    if(v!=VK_SUCCESS || !(caps.supportedUsageFlags & VK_IMAGE_USAGE_TRANSFER_DST_BIT)){
        stamp("PRESENT_STATUS","SURFACE_TRANSFER_DST_NOT_AVAILABLE");
        return 4;
    }
    uint32_t formatCount=0;
    v=getFormats(gpu,surface,&formatCount,NULL);
    if(v!=VK_SUCCESS||formatCount==0||formatCount>64){
        stamp("PRESENT_STATUS","SURFACE_FORMATS_UNAVAILABLE");
        return 5;
    }
    VkSurfaceFormatKHR formats[64];
    v=getFormats(gpu,surface,&formatCount,formats);
    if(v!=VK_SUCCESS||formatCount==0){
        stamp("PRESENT_STATUS","SURFACE_FORMAT_QUERY_FAILED");
        return 6;
    }
    VkSurfaceFormatKHR selected=formats[0];
    for(uint32_t i=0;i<formatCount;i++){
        if(formats[i].format==VK_FORMAT_B8G8R8A8_UNORM
          ||formats[i].format==VK_FORMAT_R8G8B8A8_UNORM){
            selected=formats[i];break;
        }
    }
    if(selected.format==VK_FORMAT_UNDEFINED){
        stamp("PRESENT_STATUS","SURFACE_FORMAT_UNDEFINED");
        return 7;
    }
    uint32_t modeCount=0;
    v=getModes(gpu,surface,&modeCount,NULL);
    if(v!=VK_SUCCESS||modeCount==0||modeCount>64){
        stamp("PRESENT_STATUS","SURFACE_PRESENT_MODES_UNAVAILABLE");
        return 8;
    }
    VkPresentModeKHR modes[64];
    v=getModes(gpu,surface,&modeCount,modes);
    if(v!=VK_SUCCESS){
        stamp("PRESENT_STATUS","SURFACE_PRESENT_MODES_QUERY_FAILED");
        return 9;
    }
    int haveFifo=0;
    for(uint32_t i=0;i<modeCount;i++)
        if(modes[i]==VK_PRESENT_MODE_FIFO_KHR)haveFifo=1;
    if(!haveFifo){
        stamp("PRESENT_STATUS","FIFO_PRESENT_MODE_MISSING");
        return 10;
    }
    VkExtent2D extent=caps.currentExtent;
    if(extent.width==UINT32_MAX||extent.height==UINT32_MAX) {
        extent.width=512;extent.height=288;
        if(extent.width<caps.minImageExtent.width)extent.width=caps.minImageExtent.width;
        if(extent.height<caps.minImageExtent.height)extent.height=caps.minImageExtent.height;
        if(extent.width>caps.maxImageExtent.width)extent.width=caps.maxImageExtent.width;
        if(extent.height>caps.maxImageExtent.height)extent.height=caps.maxImageExtent.height;
    }
    if(extent.width==0||extent.height==0){
        stamp("PRESENT_STATUS","SURFACE_ZERO_EXTENT");
        return 11;
    }
    printf("RM11_V475_SWAPCHAIN_EXTENT=%ux%u\n",extent.width,extent.height);
    fflush(stdout);
    float priority=1.0f;
    VkDeviceQueueCreateInfo qInfo={0};
    qInfo.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qInfo.queueFamilyIndex=family;
    qInfo.queueCount=1;
    qInfo.pQueuePriorities=&priority;
    const char *deviceExtensions[]={VK_KHR_SWAPCHAIN_EXTENSION_NAME};
    VkDeviceCreateInfo dInfo={0};
    dInfo.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dInfo.queueCreateInfoCount=1;
    dInfo.pQueueCreateInfos=&qInfo;
    dInfo.enabledExtensionCount=1;
    dInfo.ppEnabledExtensionNames=deviceExtensions;
    v=createDevice(gpu,&dInfo,NULL,&device);
    number("VK_CREATE_DEVICE_RESULT",(int)v);
    if(v!=VK_SUCCESS||device==VK_NULL_HANDLE){
        stamp("PRESENT_STATUS","DEVICE_CREATION_FAILED");
        return 12;
    }
    PFN_vkDestroyDevice destroyDevice=(PFN_vkDestroyDevice)
        getDevice(device,"vkDestroyDevice");
    PFN_vkDeviceWaitIdle deviceIdle=(PFN_vkDeviceWaitIdle)
        getDevice(device,"vkDeviceWaitIdle");
    PFN_vkGetDeviceQueue getQueue=(PFN_vkGetDeviceQueue)
        getDevice(device,"vkGetDeviceQueue");
    PFN_vkCreateSwapchainKHR createSwapchain=(PFN_vkCreateSwapchainKHR)
        getDevice(device,"vkCreateSwapchainKHR");
    PFN_vkDestroySwapchainKHR destroySwapchain=(PFN_vkDestroySwapchainKHR)
        getDevice(device,"vkDestroySwapchainKHR");
    PFN_vkGetSwapchainImagesKHR swapchainImages=(PFN_vkGetSwapchainImagesKHR)
        getDevice(device,"vkGetSwapchainImagesKHR");
    PFN_vkAcquireNextImageKHR acquire=(PFN_vkAcquireNextImageKHR)
        getDevice(device,"vkAcquireNextImageKHR");
    PFN_vkQueuePresentKHR present=(PFN_vkQueuePresentKHR)
        getDevice(device,"vkQueuePresentKHR");
    PFN_vkCreateSemaphore createSem=(PFN_vkCreateSemaphore)
        getDevice(device,"vkCreateSemaphore");
    PFN_vkDestroySemaphore destroySem=(PFN_vkDestroySemaphore)
        getDevice(device,"vkDestroySemaphore");
    PFN_vkCreateCommandPool createPool=(PFN_vkCreateCommandPool)
        getDevice(device,"vkCreateCommandPool");
    PFN_vkDestroyCommandPool destroyPool=(PFN_vkDestroyCommandPool)
        getDevice(device,"vkDestroyCommandPool");
    PFN_vkAllocateCommandBuffers allocateCmd=(PFN_vkAllocateCommandBuffers)
        getDevice(device,"vkAllocateCommandBuffers");
    PFN_vkBeginCommandBuffer beginCmd=(PFN_vkBeginCommandBuffer)
        getDevice(device,"vkBeginCommandBuffer");
    PFN_vkEndCommandBuffer endCmd=(PFN_vkEndCommandBuffer)
        getDevice(device,"vkEndCommandBuffer");
    PFN_vkCmdPipelineBarrier barrier=(PFN_vkCmdPipelineBarrier)
        getDevice(device,"vkCmdPipelineBarrier");
    PFN_vkCmdClearColorImage clear=(PFN_vkCmdClearColorImage)
        getDevice(device,"vkCmdClearColorImage");
    PFN_vkQueueSubmit queueSubmit=(PFN_vkQueueSubmit)
        getDevice(device,"vkQueueSubmit");
    if(!destroyDevice||!deviceIdle||!getQueue||!createSwapchain
       ||!destroySwapchain||!swapchainImages||!acquire||!present
       ||!createSem||!destroySem||!createPool||!destroyPool||!allocateCmd
       ||!beginCmd||!endCmd||!barrier||!clear||!queueSubmit){
        stamp("PRESENT_STATUS","DEVICE_DISPATCH_MISSING");
        outcome=13;goto cleanup_device;
    }
    uint32_t count=caps.minImageCount+1;
    if(caps.maxImageCount && count>caps.maxImageCount)count=caps.maxImageCount;
    VkCompositeAlphaFlagBitsKHR alpha=VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    if(!(caps.supportedCompositeAlpha&alpha)){
        if(caps.supportedCompositeAlpha&VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR;
        else if(caps.supportedCompositeAlpha&VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR;
        else if(caps.supportedCompositeAlpha&VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR;
        else {stamp("PRESENT_STATUS","COMPOSITE_ALPHA_NOT_SUPPORTED");
            outcome=14;goto cleanup_device;}
    }
    VkSwapchainCreateInfoKHR sw={0};
    sw.sType=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    sw.surface=surface;
    sw.minImageCount=count;
    sw.imageFormat=selected.format;
    sw.imageColorSpace=selected.colorSpace;
    sw.imageExtent=extent;
    sw.imageArrayLayers=1;
    sw.imageUsage=VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    sw.imageSharingMode=VK_SHARING_MODE_EXCLUSIVE;
    sw.preTransform=caps.currentTransform;
    sw.compositeAlpha=alpha;
    sw.presentMode=VK_PRESENT_MODE_FIFO_KHR;
    sw.clipped=VK_TRUE;
    v=createSwapchain(device,&sw,NULL,&swapchain);
    number("VK_CREATE_SWAPCHAIN_RESULT",(int)v);
    if(v!=VK_SUCCESS||swapchain==VK_NULL_HANDLE){
        stamp("PRESENT_STATUS","SWAPCHAIN_CREATION_FAILED");
        outcome=15;goto cleanup_device;
    }
    uint32_t n=0;
    v=swapchainImages(device,swapchain,&n,NULL);
    if(v!=VK_SUCCESS||n==0||n>16){
        stamp("PRESENT_STATUS","SWAPCHAIN_IMAGES_INVALID");
        outcome=16;goto cleanup_device;
    }
    VkImage images[16];
    v=swapchainImages(device,swapchain,&n,images);
    if(v!=VK_SUCCESS){
        stamp("PRESENT_STATUS","SWAPCHAIN_IMAGE_QUERY_FAILED");
        outcome=17;goto cleanup_device;
    }
    VkCommandPoolCreateInfo pi={0};
    pi.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pi.queueFamilyIndex=family;
    v=createPool(device,&pi,NULL,&pool);
    if(v!=VK_SUCCESS){
        stamp("PRESENT_STATUS","COMMAND_POOL_FAILED");
        outcome=18;goto cleanup_device;
    }
    VkSemaphoreCreateInfo si={0};
    si.sType=VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    v=createSem(device,&si,NULL,&acquired);
    if(v!=VK_SUCCESS){outcome=19;goto cleanup_device;}
    v=createSem(device,&si,NULL,&rendered);
    if(v!=VK_SUCCESS){outcome=20;goto cleanup_device;}
    uint32_t index=0;
    v=acquire(device,swapchain,2000000000ULL,acquired,VK_NULL_HANDLE,&index);
    number("VK_ACQUIRE_IMAGE_RESULT",(int)v);
    if((v!=VK_SUCCESS&&v!=VK_SUBOPTIMAL_KHR)||index>=n){
        stamp("PRESENT_STATUS","ACQUIRE_FAILED");
        outcome=21;goto cleanup_device;
    }
    VkCommandBufferAllocateInfo ai={0};
    ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool=pool;
    ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount=1;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    v=allocateCmd(device,&ai,&cmd);
    if(v!=VK_SUCCESS){outcome=22;goto cleanup_device;}
    VkCommandBufferBeginInfo bi={0};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    v=beginCmd(cmd,&bi);
    if(v!=VK_SUCCESS){outcome=23;goto cleanup_device;}
    VkImageMemoryBarrier imageBar={0};
    imageBar.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    imageBar.oldLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    imageBar.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    imageBar.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    imageBar.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    imageBar.image=images[index];
    imageBar.subresourceRange.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    imageBar.subresourceRange.levelCount=1;
    imageBar.subresourceRange.layerCount=1;
    imageBar.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier(cmd,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,
            0,0,NULL,0,NULL,1,&imageBar);
    VkClearColorValue magenta={{0.95f,0.10f,0.60f,1.00f}};
    VkImageSubresourceRange range={0};
    range.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    range.levelCount=1;
    range.layerCount=1;
    clear(cmd,images[index],VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&magenta,1,&range);
    imageBar.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    imageBar.dstAccessMask=0;
    imageBar.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    imageBar.newLayout=VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    barrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
            0,0,NULL,0,NULL,1,&imageBar);
    v=endCmd(cmd);
    if(v!=VK_SUCCESS){outcome=24;goto cleanup_device;}
    VkQueue queue=VK_NULL_HANDLE;
    getQueue(device,family,0,&queue);
    if(queue==VK_NULL_HANDLE){outcome=25;goto cleanup_device;}
    VkPipelineStageFlags waitStage=VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo submit={0};
    submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.waitSemaphoreCount=1;
    submit.pWaitSemaphores=&acquired;
    submit.pWaitDstStageMask=&waitStage;
    submit.commandBufferCount=1;
    submit.pCommandBuffers=&cmd;
    submit.signalSemaphoreCount=1;
    submit.pSignalSemaphores=&rendered;
    v=queueSubmit(queue,1,&submit,VK_NULL_HANDLE);
    number("VK_QUEUE_SUBMIT_RESULT",(int)v);
    if(v!=VK_SUCCESS){outcome=26;goto cleanup_device;}
    VkPresentInfoKHR p={0};
    p.sType=VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    p.waitSemaphoreCount=1;
    p.pWaitSemaphores=&rendered;
    p.swapchainCount=1;
    p.pSwapchains=&swapchain;
    p.pImageIndices=&index;
    v=present(queue,&p);
    number("VK_QUEUE_PRESENT_RESULT",(int)v);
    if(v!=VK_SUCCESS&&v!=VK_SUBOPTIMAL_KHR){
        stamp("PRESENT_STATUS","VK_QUEUE_PRESENT_FAILED");
        outcome=27;goto cleanup_device;
    }
    stamp("PRESENT_STATUS","MAGENTA_FRAME_SUBMITTED_VIA_XLIB");
    stamp("FRAME_COLOR","MAGENTA_0xF21999");
    stamp("PIXELCOPY_VISUAL_CHECK","NOT_CONFIRMED");
    v=deviceIdle(device);
    number("VK_DEVICE_WAIT_IDLE_RESULT",(int)v);
    if(v!=VK_SUCCESS){outcome=28;goto cleanup_device;}
    outcome=0;
    sleep(3); /* Keep X11 frame visible; screenshot is external verification. */
cleanup_device:
    if(deviceIdle && device!=VK_NULL_HANDLE)deviceIdle(device);
    if(pool && destroyPool)destroyPool(device,pool,NULL);
    if(acquired && destroySem)destroySem(device,acquired,NULL);
    if(rendered && destroySem)destroySem(device,rendered,NULL);
    if(swapchain && destroySwapchain)destroySwapchain(device,swapchain,NULL);
    if(destroyDevice)destroyDevice(device,NULL);
    return outcome;
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
    uint32_t winningDevice=0,winningFamily=0;
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
            if(v==VK_SUCCESS && yes==VK_TRUE
               &&(qp[q].queueFlags&VK_QUEUE_GRAPHICS_BIT)){
                supportsPresent=1;
                winningDevice=i;
                winningFamily=q;
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
    else {
        int presentResult=rm11_present_frame(instance,gpus[winningDevice],
                                             surface,winningFamily,gip);
        number("FRAME_PRESENT_TEST_RESULT",presentResult);
        if(presentResult!=0)result=30+presentResult;
    }
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
