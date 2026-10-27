/*
 * RM11 v475: bounded, independent, GREEN Vulkan Xlib swapchain clear+present.
 * Purpose: distinguish VkSurface success (v474) from frame submission.
 * Isolated Android PIE signed within APK; does not run Wine or the game.
 * VkQueuePresent success is not physical screen pixel confirmation.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <vulkan/vulkan.h>

#define EXT_MAX 512u
#define GPU_MAX 8u
#define Q_MAX 32u
#define FRAMES 1u

typedef struct {
    VkStructureType sType;
    const void *pNext;
    VkFlags flags;
    void *dpy;
    unsigned long window;
} XlibCreateInfo;
typedef VkResult (VKAPI_PTR *CreateXlibSurface)(VkInstance,
    const XlibCreateInfo *,const VkAllocationCallbacks *,VkSurfaceKHR *);
typedef void *(*OpenDisplay)(const char *);
typedef unsigned long (*DefaultRoot)(void *);
typedef int (*DefaultScreen)(void *);
typedef int (*DisplayDimension)(void *,int);
typedef unsigned long (*CreateWindow)(void *,unsigned long,int,int,
    unsigned int,unsigned int,unsigned int,unsigned long,unsigned long);
typedef int (*WindowAction)(void *,unsigned long);
typedef int (*DisplayAction)(void *);
static void out(const char *key,const char *value) {
    printf("RM11_V475_%s=%s\n",key,value);fflush(stdout);
}
static void num(const char *key,int value) {
    printf("RM11_V475_%s=%d\n",key,value);fflush(stdout);
}
static int supported(const VkExtensionProperties *exts,uint32_t n,const char *name) {
    for(uint32_t i=0;i<n;i++)
        if(strcmp(exts[i].extensionName,name)==0)return 1;
    return 0;
}
static uint32_t bounded(uint32_t value,uint32_t min,uint32_t max) {
    if(value<min)return min;
    if(max && value>max)return max;
    return value;
}
#define LOAD(type,variable,source,name) type variable=(type)source(name)

int main(void) {
    out("STAGE","START_ISOLATED_GREEN_PRESENT");
    out("WINE_OR_GAME_STARTED","false");
    out("EXPECTED_COLOR","BRIGHT_GREEN");
    int result=1;
    void *xlib=NULL,*vk=NULL,*display=NULL;
    unsigned long window=0;
    VkInstance instance=VK_NULL_HANDLE;
    VkSurfaceKHR surface=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkSwapchainKHR swapchain=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    VkSemaphore imageReady=VK_NULL_HANDLE,renderFinished=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    PFN_vkGetInstanceProcAddr gip=NULL;
    PFN_vkGetDeviceProcAddr gdp=NULL;
    PFN_vkDestroyInstance destroyInstance=NULL;
    PFN_vkDestroySurfaceKHR destroySurface=NULL;
    PFN_vkDestroyDevice destroyDevice=NULL;
    PFN_vkDestroySwapchainKHR destroySwapchain=NULL;
    PFN_vkDestroyCommandPool destroyPool=NULL;
    PFN_vkDestroySemaphore destroySemaphore=NULL;
    PFN_vkDestroyFence destroyFence=NULL;
    DisplayAction closeDisplay=NULL,flush=NULL;
    WindowAction destroyWindow=NULL;
    const char *phase="BEFORE_X11";

    xlib=dlopen("libX11.so",RTLD_NOW|RTLD_LOCAL);
    if(!xlib){out("ERROR","XLIB_LOADER_FAILED");result=10;goto done;}
    OpenDisplay openDisplay=(OpenDisplay)dlsym(xlib,"XOpenDisplay");
    DefaultRoot root=(DefaultRoot)dlsym(xlib,"XDefaultRootWindow");
    DefaultScreen screen=(DefaultScreen)dlsym(xlib,"XDefaultScreen");
    DisplayDimension width=(DisplayDimension)dlsym(xlib,"XDisplayWidth");
    DisplayDimension height=(DisplayDimension)dlsym(xlib,"XDisplayHeight");
    CreateWindow createWindow=(CreateWindow)dlsym(xlib,"XCreateSimpleWindow");
    WindowAction mapWindow=(WindowAction)dlsym(xlib,"XMapWindow");
    destroyWindow=(WindowAction)dlsym(xlib,"XDestroyWindow");
    flush=(DisplayAction)dlsym(xlib,"XFlush");
    closeDisplay=(DisplayAction)dlsym(xlib,"XCloseDisplay");
    if(!openDisplay||!root||!screen||!width||!height||!createWindow
       ||!mapWindow||!destroyWindow||!flush||!closeDisplay){
        out("ERROR","XLIB_EXPORT_MISSING");result=11;goto done;
    }
    display=openDisplay("127.0.0.1:2");
    if(!display){out("ERROR","X11_CONNECT_FAILED");result=12;goto done;}
    out("X11_CONNECTED","true");
    int xw=width(display,screen(display));
    int xh=height(display,screen(display));
    if(xw<200||xh<160||xw>8192||xh>8192) {
        out("ERROR","X11_INVALID_ROOT_SIZE");result=13;goto done;
    }
    unsigned int w=(unsigned int)(xw>1200?1100:xw-50);
    unsigned int h=(unsigned int)(xh>720?620:xh-50);
    window=createWindow(display,root(display),
         (xw-(int)w)/2,(xh-(int)h)/2,w,h,0,0,0);
    if(!window){out("ERROR","X11_CREATE_WINDOW_FAILED");result=14;goto done;}
    mapWindow(display,window);
    flush(display);
    out("X11_WINDOW","MAPPED");
    phase="PRIVATE_LOADER";
    vk=dlopen("librm11_vkloader_v473.so",RTLD_NOW|RTLD_LOCAL);
    if(!vk){out("ERROR","PRIVATE_LOADER_FAILED");result=15;goto done;}
    gip=(PFN_vkGetInstanceProcAddr)dlsym(vk,"vkGetInstanceProcAddr");
    PFN_vkCreateInstance createInstance=(PFN_vkCreateInstance)dlsym(vk,"vkCreateInstance");
    PFN_vkEnumerateInstanceExtensionProperties ext=
        (PFN_vkEnumerateInstanceExtensionProperties)dlsym(vk,"vkEnumerateInstanceExtensionProperties");
    if(!gip||!createInstance||!ext){out("ERROR","LOADER_EXPORTS_MISSING");result=16;goto done;}
    uint32_t count=0;
    VkResult r=ext(NULL,&count,NULL);
    if(r!=VK_SUCCESS||count>EXT_MAX){out("ERROR","EXTENSION_COUNT_FAILED");result=17;goto done;}
    VkExtensionProperties properties[EXT_MAX];
    r=ext(NULL,&count,properties);
    if(r!=VK_SUCCESS||!supported(properties,count,VK_KHR_SURFACE_EXTENSION_NAME)
      ||!supported(properties,count,"VK_KHR_xlib_surface")){
        out("ERROR","X11_VULKAN_INSTANCE_EXTENSION_MISSING");result=18;goto done;
    }
    const char *instanceExt[]={VK_KHR_SURFACE_EXTENSION_NAME,"VK_KHR_xlib_surface"};
    VkApplicationInfo app={0};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="RM11 isolated Xlib green swapchain";
    app.apiVersion=VK_API_VERSION_1_1;
    VkInstanceCreateInfo ci={0};
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo=&app;
    ci.enabledExtensionCount=2;
    ci.ppEnabledExtensionNames=instanceExt;
    r=createInstance(&ci,NULL,&instance);
    num("CREATE_INSTANCE_RESULT",(int)r);
    if(r!=VK_SUCCESS||instance==VK_NULL_HANDLE){result=19;goto done;}
    destroyInstance=(PFN_vkDestroyInstance)gip(instance,"vkDestroyInstance");
    destroySurface=(PFN_vkDestroySurfaceKHR)gip(instance,"vkDestroySurfaceKHR");
    /* Use manually declared ABI to avoid desktop Xlib NDK headers. */
    CreateXlibSurface createXlib=(CreateXlibSurface)gip(instance,"vkCreateXlibSurfaceKHR");
    PFN_vkEnumeratePhysicalDevices physical=
       (PFN_vkEnumeratePhysicalDevices)gip(instance,"vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceQueueFamilyProperties queueProperties=
       (PFN_vkGetPhysicalDeviceQueueFamilyProperties)gip(instance,"vkGetPhysicalDeviceQueueFamilyProperties");
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR surfaceSupport=
       (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)gip(instance,"vkGetPhysicalDeviceSurfaceSupportKHR");
    PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR surfaceCaps=
       (PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR)gip(instance,"vkGetPhysicalDeviceSurfaceCapabilitiesKHR");
    PFN_vkGetPhysicalDeviceSurfaceFormatsKHR surfaceFormats=
       (PFN_vkGetPhysicalDeviceSurfaceFormatsKHR)gip(instance,"vkGetPhysicalDeviceSurfaceFormatsKHR");
    PFN_vkCreateDevice createDevice=(PFN_vkCreateDevice)gip(instance,"vkCreateDevice");
    gdp=(PFN_vkGetDeviceProcAddr)gip(instance,"vkGetDeviceProcAddr");
    if(!destroyInstance||!destroySurface||!createXlib||!physical||!queueProperties
       ||!surfaceSupport||!surfaceCaps||!surfaceFormats||!createDevice||!gdp) {
        out("ERROR","INSTANCE_DISPATCH_INCOMPLETE");result=20;goto done;
    }
    XlibCreateInfo xci={0};
    xci.sType=(VkStructureType)1000004000;
    xci.dpy=display;xci.window=window;
    r=createXlib(instance,&xci,NULL,&surface);
    num("CREATE_XLIB_SURFACE_RESULT",(int)r);
    if(r!=VK_SUCCESS||surface==VK_NULL_HANDLE){result=21;goto done;}
    out("SURFACE_CREATED","true");
    uint32_t numGpu=0;
    r=physical(instance,&numGpu,NULL);
    if(r!=VK_SUCCESS||numGpu==0||numGpu>GPU_MAX){result=22;goto done;}
    VkPhysicalDevice gpus[GPU_MAX];
    r=physical(instance,&numGpu,gpus);
    if(r!=VK_SUCCESS){result=23;goto done;}
    VkPhysicalDevice gpu=VK_NULL_HANDLE;
    uint32_t queueIndex=UINT32_MAX;
    for(uint32_t g=0;g<numGpu;g++){
        uint32_t nq=0;
        queueProperties(gpus[g],&nq,NULL);
        if(nq>Q_MAX)continue;
        VkQueueFamilyProperties q[Q_MAX];
        queueProperties(gpus[g],&nq,q);
        for(uint32_t i=0;i<nq;i++){
            VkBool32 present=VK_FALSE;
            r=surfaceSupport(gpus[g],i,surface,&present);
            if(r==VK_SUCCESS && present && (q[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)){
                gpu=gpus[g];queueIndex=i;break;
            }
        }
        if(gpu!=VK_NULL_HANDLE)break;
    }
    if(gpu==VK_NULL_HANDLE){out("ERROR","NO_GRAPHICS_PRESENT_QUEUE");result=24;goto done;}
    num("PRESENT_QUEUE_FAMILY",(int)queueIndex);
    PFN_vkEnumerateDeviceExtensionProperties deviceExtensions=
       (PFN_vkEnumerateDeviceExtensionProperties)gip(instance,"vkEnumerateDeviceExtensionProperties");
    if(!deviceExtensions){result=25;goto done;}
    uint32_t nex=0;
    r=deviceExtensions(gpu,NULL,&nex,NULL);
    if(r!=VK_SUCCESS||nex>EXT_MAX){result=26;goto done;}
    VkExtensionProperties dprops[EXT_MAX];
    r=deviceExtensions(gpu,NULL,&nex,dprops);
    if(r!=VK_SUCCESS || !supported(dprops,nex,VK_KHR_SWAPCHAIN_EXTENSION_NAME)){
        out("ERROR","SWAPCHAIN_DEVICE_EXTENSION_MISSING");result=27;goto done;
    }
    float priority=1.0f;
    VkDeviceQueueCreateInfo qci={0};
    qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex=queueIndex;qci.queueCount=1;qci.pQueuePriorities=&priority;
    const char *deviceEx[]={VK_KHR_SWAPCHAIN_EXTENSION_NAME};
    VkDeviceCreateInfo dci={0};
    dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount=1;dci.pQueueCreateInfos=&qci;
    dci.enabledExtensionCount=1;dci.ppEnabledExtensionNames=deviceEx;
    r=createDevice(gpu,&dci,NULL,&device);
    num("CREATE_DEVICE_RESULT",(int)r);
    if(r!=VK_SUCCESS||device==VK_NULL_HANDLE){result=28;goto done;}
    destroyDevice=(PFN_vkDestroyDevice)gdp(device,"vkDestroyDevice");
    PFN_vkDeviceWaitIdle deviceIdle=(PFN_vkDeviceWaitIdle)gdp(device,"vkDeviceWaitIdle");
    PFN_vkGetDeviceQueue deviceQueue=(PFN_vkGetDeviceQueue)gdp(device,"vkGetDeviceQueue");
    PFN_vkCreateSwapchainKHR createSwapchain=(PFN_vkCreateSwapchainKHR)gdp(device,"vkCreateSwapchainKHR");
    destroySwapchain=(PFN_vkDestroySwapchainKHR)gdp(device,"vkDestroySwapchainKHR");
    PFN_vkGetSwapchainImagesKHR images=(PFN_vkGetSwapchainImagesKHR)gdp(device,"vkGetSwapchainImagesKHR");
    PFN_vkAcquireNextImageKHR acquire=(PFN_vkAcquireNextImageKHR)gdp(device,"vkAcquireNextImageKHR");
    PFN_vkQueuePresentKHR present=(PFN_vkQueuePresentKHR)gdp(device,"vkQueuePresentKHR");
    PFN_vkCreateCommandPool createPool=(PFN_vkCreateCommandPool)gdp(device,"vkCreateCommandPool");
    destroyPool=(PFN_vkDestroyCommandPool)gdp(device,"vkDestroyCommandPool");
    PFN_vkAllocateCommandBuffers allocate=(PFN_vkAllocateCommandBuffers)gdp(device,"vkAllocateCommandBuffers");
    PFN_vkBeginCommandBuffer begin=(PFN_vkBeginCommandBuffer)gdp(device,"vkBeginCommandBuffer");
    PFN_vkEndCommandBuffer end=(PFN_vkEndCommandBuffer)gdp(device,"vkEndCommandBuffer");
    PFN_vkCmdPipelineBarrier barrier=(PFN_vkCmdPipelineBarrier)gdp(device,"vkCmdPipelineBarrier");
    PFN_vkCmdClearColorImage clear=(PFN_vkCmdClearColorImage)gdp(device,"vkCmdClearColorImage");
    PFN_vkQueueSubmit submit=(PFN_vkQueueSubmit)gdp(device,"vkQueueSubmit");
    PFN_vkCreateSemaphore createSemaphore=(PFN_vkCreateSemaphore)gdp(device,"vkCreateSemaphore");
    destroySemaphore=(PFN_vkDestroySemaphore)gdp(device,"vkDestroySemaphore");
    PFN_vkCreateFence createFence=(PFN_vkCreateFence)gdp(device,"vkCreateFence");
    destroyFence=(PFN_vkDestroyFence)gdp(device,"vkDestroyFence");
    PFN_vkWaitForFences waitFences=(PFN_vkWaitForFences)gdp(device,"vkWaitForFences");
    if(!destroyDevice||!deviceIdle||!deviceQueue||!createSwapchain||!destroySwapchain
       ||!images||!acquire||!present||!createPool||!destroyPool||!allocate||!begin
       ||!end||!barrier||!clear||!submit||!createSemaphore||!destroySemaphore
       ||!createFence||!destroyFence||!waitFences) {
        out("ERROR","DEVICE_DISPATCH_INCOMPLETE");result=29;goto done;
    }
    VkSurfaceCapabilitiesKHR caps;
    r=surfaceCaps(gpu,surface,&caps);
    if(r!=VK_SUCCESS ||!(caps.supportedUsageFlags&VK_IMAGE_USAGE_TRANSFER_DST_BIT)){
        out("ERROR","SURFACE_TRANSFER_DST_UNSUPPORTED");result=30;goto done;
    }
    uint32_t nfmt=0;
    r=surfaceFormats(gpu,surface,&nfmt,NULL);
    if(r!=VK_SUCCESS||nfmt==0||nfmt>128){result=31;goto done;}
    VkSurfaceFormatKHR formats[128];
    r=surfaceFormats(gpu,surface,&nfmt,formats);
    if(r!=VK_SUCCESS){result=32;goto done;}
    VkSurfaceFormatKHR selected=formats[0];
    if(nfmt==1&&selected.format==VK_FORMAT_UNDEFINED)
        selected.format=VK_FORMAT_B8G8R8A8_UNORM;
    for(uint32_t i=0;i<nfmt;i++)
        if(formats[i].format==VK_FORMAT_B8G8R8A8_UNORM &&
           formats[i].colorSpace==VK_COLOR_SPACE_SRGB_NONLINEAR_KHR){
            selected=formats[i];break;
        }
    VkExtent2D extent=caps.currentExtent;
    if(extent.width==UINT32_MAX){
        extent.width=bounded(w,caps.minImageExtent.width,caps.maxImageExtent.width);
        extent.height=bounded(h,caps.minImageExtent.height,caps.maxImageExtent.height);
    }
    if(extent.width==0||extent.height==0){result=33;goto done;}
    VkCompositeAlphaFlagBitsKHR alpha=VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    if(!(caps.supportedCompositeAlpha&alpha)){
        VkCompositeAlphaFlagBitsKHR values[]={
            VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR,
            VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR,
            VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR
        };
        int found=0;
        for(unsigned int i=0;i<3;i++)if(caps.supportedCompositeAlpha&values[i]){
            alpha=values[i];found=1;break;
        }
        if(!found){result=34;goto done;}
    }
    VkSwapchainCreateInfoKHR sci={0};
    sci.sType=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    sci.surface=surface;
    sci.minImageCount=bounded(caps.minImageCount+1,caps.minImageCount,caps.maxImageCount);
    sci.imageFormat=selected.format;
    sci.imageColorSpace=selected.colorSpace;
    sci.imageExtent=extent;
    sci.imageArrayLayers=1;
    sci.imageUsage=VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    sci.imageSharingMode=VK_SHARING_MODE_EXCLUSIVE;
    sci.preTransform=caps.currentTransform;
    sci.compositeAlpha=alpha;
    sci.presentMode=VK_PRESENT_MODE_FIFO_KHR;
    sci.clipped=VK_TRUE;
    r=createSwapchain(device,&sci,NULL,&swapchain);
    num("CREATE_SWAPCHAIN_RESULT",(int)r);
    if(r!=VK_SUCCESS||swapchain==VK_NULL_HANDLE){result=35;goto done;}
    uint32_t ni=0;
    r=images(device,swapchain,&ni,NULL);
    if(r!=VK_SUCCESS||ni==0||ni>8){result=36;goto done;}
    VkImage swapImages[8];
    r=images(device,swapchain,&ni,swapImages);
    if(r!=VK_SUCCESS){result=37;goto done;}
    out("SWAPCHAIN_CREATED","true");
    VkQueue queue=VK_NULL_HANDLE;
    deviceQueue(device,queueIndex,0,&queue);
    if(queue==VK_NULL_HANDLE){result=38;goto done;}
    VkSemaphoreCreateInfo semci={0};
    semci.sType=VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    r=createSemaphore(device,&semci,NULL,&imageReady);
    if(r!=VK_SUCCESS){result=39;goto done;}
    r=createSemaphore(device,&semci,NULL,&renderFinished);
    if(r!=VK_SUCCESS){result=40;goto done;}
    VkFenceCreateInfo fci={0};
    fci.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    r=createFence(device,&fci,NULL,&fence);
    if(r!=VK_SUCCESS){result=41;goto done;}
    uint32_t imageIndex=0;
    r=acquire(device,swapchain,3000000000ULL,imageReady,VK_NULL_HANDLE,&imageIndex);
    num("ACQUIRE_NEXT_IMAGE_RESULT",(int)r);
    if((r!=VK_SUCCESS && r!=VK_SUBOPTIMAL_KHR)||imageIndex>=ni){result=42;goto done;}
    VkCommandPoolCreateInfo pci={0};
    pci.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pci.queueFamilyIndex=queueIndex;
    r=createPool(device,&pci,NULL,&pool);
    if(r!=VK_SUCCESS){result=43;goto done;}
    VkCommandBufferAllocateInfo cai={0};
    cai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cai.commandPool=pool;cai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount=1;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    r=allocate(device,&cai,&cmd);
    if(r!=VK_SUCCESS){result=44;goto done;}
    VkCommandBufferBeginInfo bi={0};bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    r=begin(cmd,&bi);
    if(r!=VK_SUCCESS){result=45;goto done;}
    VkImageMemoryBarrier pre={0};
    pre.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    pre.oldLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    pre.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    pre.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    pre.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    pre.image=swapImages[imageIndex];
    pre.subresourceRange.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    pre.subresourceRange.levelCount=1;pre.subresourceRange.layerCount=1;
    pre.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier(cmd,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,
        0,0,NULL,0,NULL,1,&pre);
    VkClearColorValue green={.float32={0.05f,0.85f,0.15f,1.0f}};
    VkImageSubresourceRange range={0};
    range.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    range.levelCount=1;range.layerCount=1;
    clear(cmd,swapImages[imageIndex],VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&green,1,&range);
    VkImageMemoryBarrier post=pre;
    post.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    post.newLayout=VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    post.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    post.dstAccessMask=0;
    barrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
        0,0,NULL,0,NULL,1,&post);
    r=end(cmd);
    if(r!=VK_SUCCESS){result=46;goto done;}
    VkPipelineStageFlags waitStage=VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo si={0};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.waitSemaphoreCount=1;si.pWaitSemaphores=&imageReady;
    si.pWaitDstStageMask=&waitStage;
    si.commandBufferCount=1;si.pCommandBuffers=&cmd;
    si.signalSemaphoreCount=1;si.pSignalSemaphores=&renderFinished;
    r=submit(queue,1,&si,fence);
    num("QUEUE_SUBMIT_RESULT",(int)r);
    if(r!=VK_SUCCESS){result=47;goto done;}
    r=waitFences(device,1,&fence,VK_TRUE,2500000000ULL);
    num("GPU_FENCE_WAIT_RESULT",(int)r);
    if(r!=VK_SUCCESS){result=48;goto done;}
    out("GPU_GREEN_CLEAR_FINISHED","true");
    VkPresentInfoKHR p={0};
    p.sType=VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    p.waitSemaphoreCount=1;p.pWaitSemaphores=&renderFinished;
    p.swapchainCount=1;p.pSwapchains=&swapchain;
    p.pImageIndices=&imageIndex;
    r=present(queue,&p);
    num("QUEUE_PRESENT_RESULT",(int)r);
    if(r!=VK_SUCCESS&&r!=VK_SUBOPTIMAL_KHR){result=49;goto done;}
    out("GREEN_FRAME_PRESENT_ENQUEUED","true");
    out("ACTUAL_ANDROID_SURFACE_PIXELS","NOT_SAMPLED_IN_CHILD");
    flush(display);
    /* Hold visible long enough for Lorie pixel-copy sampling while alive. */
    sleep(3);
    result=0;
done:
    if(device!=VK_NULL_HANDLE){
        if(destroyDevice){
            PFN_vkDeviceWaitIdle idle=(PFN_vkDeviceWaitIdle)gdp(device,"vkDeviceWaitIdle");
            if(idle)idle(device);
        }
        if(destroyFence&&fence!=VK_NULL_HANDLE)destroyFence(device,fence,NULL);
        if(destroySemaphore&&renderFinished!=VK_NULL_HANDLE)
            destroySemaphore(device,renderFinished,NULL);
        if(destroySemaphore&&imageReady!=VK_NULL_HANDLE)
            destroySemaphore(device,imageReady,NULL);
        if(destroyPool&&pool!=VK_NULL_HANDLE)destroyPool(device,pool,NULL);
        if(destroySwapchain&&swapchain!=VK_NULL_HANDLE)
            destroySwapchain(device,swapchain,NULL);
        if(destroyDevice)destroyDevice(device,NULL);
    }
    if(instance!=VK_NULL_HANDLE){
        if(destroySurface&&surface!=VK_NULL_HANDLE)destroySurface(instance,surface,NULL);
        if(destroyInstance)destroyInstance(instance,NULL);
    }
    if(vk)dlclose(vk);
    if(display&&window&&destroyWindow)destroyWindow(display,window);
    if(display&&flush)flush(display);
    if(display&&closeDisplay)closeDisplay(display);
    if(xlib)dlclose(xlib);
    out("LAST_STAGE",phase);
    num("EXIT_CODE",result);
    return result;
}
