/*
 * RM11 v4.90.5 — signed private Turnip GPU-color -> Android ANativeWindow
 * NativeWindow display is CPU-blitted from a GPU-produced VkBuffer, and is
 * deliberately NOT a private Vulkan WSI/Swapchain or Wine/DXVK proof.
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <vulkan/vulkan.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

typedef PFN_vkVoidFunction (*rm11_gpa)(VkInstance,const char *);
typedef VkResult (*rm11_negotiate)(uint32_t *);
#define VK_CALL(expr,where) do {stage=where;rc=(expr);if(rc!=VK_SUCCESS)goto out;}while(0)
#define LOOKUP(dst,expr) do {PFN_vkVoidFunction _raw=(expr);memcpy(&(dst),&_raw,sizeof(dst));\
 if(!(dst)){stage="VULKAN_FUNCTION_MISSING_" #dst;goto out;}}while(0)

JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RM11TurnipBufferSurface_nativeRun(
    JNIEnv *env,jclass unused,jobject surface,jstring pathString,jint requested) {
    (void)unused;
    char report[1250];
    const char *stage="START",*path=NULL;
    VkResult rc=VK_ERROR_INITIALIZATION_FAILED;
    void *library=NULL, *mapped=NULL;
    ANativeWindow *window=NULL;
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkBuffer buffer=VK_NULL_HANDLE;
    VkDeviceMemory memory=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    VkQueue queue=VK_NULL_HANDLE;
    uint32_t vendor=0,deviceId=0,frames=0,gpuMatches=0;
    int32_t lastWindowStatus=-9999;
    bool everPosted=false;
    rm11_gpa gpa=NULL;
    PFN_vkDestroyInstance destroyInstance=NULL;
    PFN_vkDestroyDevice destroyDevice=NULL;
    PFN_vkDeviceWaitIdle waitIdle=NULL;
    PFN_vkDestroyBuffer destroyBuffer=NULL;
    PFN_vkFreeMemory freeMemory=NULL;
    PFN_vkUnmapMemory unmapMemory=NULL;
    PFN_vkDestroyCommandPool destroyPool=NULL;
    PFN_vkDestroyFence destroyFence=NULL;
    if(!surface || !pathString) {stage="SURFACE_OR_DRIVER_MISSING";goto out;}
    path=(*env)->GetStringUTFChars(env,pathString,NULL);
    if(!path){stage="SIGNED_PATH_READ_FAILED";goto out;}
    const char suffix[]="/libvulkan_freedreno.so";
    size_t n=strnlen(path,4096);
    if(n>=4096 || n<=sizeof(suffix)-1 ||
       strcmp(path+n-sizeof(suffix)+1,suffix)!=0 ||
       strncmp(path,"/data/app/",10)!=0 ||
       strstr(path,"/../") || strstr(path,"//")){
        stage="SIGNED_DRIVER_PATH_REJECTED";goto out;
    }
    stage="PRIVATE_TURNIP_DLOPEN";
    library=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!library){stage="PRIVATE_TURNIP_DLOPEN_FAILED";goto out;}
    void *sym=dlsym(library,"vk_icdGetInstanceProcAddr");
    if(!sym||sizeof(sym)!=sizeof(gpa)){stage="ICD_ENTRYPOINT_MISSING";goto out;}
    memcpy(&gpa,&sym,sizeof(gpa));
    sym=dlsym(library,"vk_icdNegotiateLoaderICDInterfaceVersion");
    if(sym&&sizeof(sym)==sizeof(rm11_negotiate)){
        rm11_negotiate negotiate=NULL;
        memcpy(&negotiate,&sym,sizeof(sym));
        uint32_t version=7;
        if(negotiate(&version)!=VK_SUCCESS || version<1){
            stage="ICD_NEGOTIATE_FAILED";goto out;
        }
    }
    PFN_vkCreateInstance createInstance=NULL;
    LOOKUP(createInstance,gpa(VK_NULL_HANDLE,"vkCreateInstance"));
    VkApplicationInfo app={.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
       .pApplicationName="RM11-PRIVATE-GPU-PIXEL-BRIDGE",.apiVersion=VK_API_VERSION_1_1};
    VkInstanceCreateInfo instanceInfo={.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
       .pApplicationInfo=&app};
    VK_CALL(createInstance(&instanceInfo,NULL,&instance),"CREATE_INSTANCE");
    LOOKUP(destroyInstance,gpa(instance,"vkDestroyInstance"));
    PFN_vkEnumeratePhysicalDevices enumerate=NULL;
    PFN_vkGetPhysicalDeviceProperties getProperties=NULL;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties getFamilies=NULL;
    PFN_vkGetPhysicalDeviceMemoryProperties getMemoryProperties=NULL;
    PFN_vkCreateDevice createDevice=NULL;
    PFN_vkGetDeviceProcAddr gdpa=NULL;
    LOOKUP(enumerate,gpa(instance,"vkEnumeratePhysicalDevices"));
    LOOKUP(getProperties,gpa(instance,"vkGetPhysicalDeviceProperties"));
    LOOKUP(getFamilies,gpa(instance,"vkGetPhysicalDeviceQueueFamilyProperties"));
    LOOKUP(getMemoryProperties,gpa(instance,"vkGetPhysicalDeviceMemoryProperties"));
    LOOKUP(createDevice,gpa(instance,"vkCreateDevice"));
    LOOKUP(gdpa,gpa(instance,"vkGetDeviceProcAddr"));
    uint32_t count=0;
    VK_CALL(enumerate(instance,&count,NULL),"ENUMERATE_GPU_COUNT");
    if(count==0||count>8){stage="INVALID_GPU_COUNT";goto out;}
    VkPhysicalDevice candidates[8]={0};
    VK_CALL(enumerate(instance,&count,candidates),"ENUMERATE_GPU_LIST");
    if(count==0){stage="NO_GPU";goto out;}
    VkPhysicalDevice physical=candidates[0];
    VkPhysicalDeviceProperties props;
    getProperties(physical,&props);
    vendor=props.vendorID;deviceId=props.deviceID;
    uint32_t countQueues=0,queueFamily=UINT32_MAX;
    getFamilies(physical,&countQueues,NULL);
    if(countQueues==0||countQueues>128){stage="INVALID_QUEUE_COUNT";goto out;}
    VkQueueFamilyProperties families[128]={0};
    getFamilies(physical,&countQueues,families);
    for(uint32_t i=0;i<countQueues;i++){
        if(families[i].queueCount>0 &&
           (families[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)){
           queueFamily=i;break;
        }
    }
    if(queueFamily==UINT32_MAX){stage="NO_GRAPHICS_QUEUE";goto out;}
    float priority=1.0f;
    VkDeviceQueueCreateInfo queueInfo={.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex=queueFamily,.queueCount=1,.pQueuePriorities=&priority};
    VkDeviceCreateInfo dci={.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount=1,.pQueueCreateInfos=&queueInfo};
    VK_CALL(createDevice(physical,&dci,NULL,&device),"CREATE_DEVICE");
    PFN_vkGetDeviceQueue getQueue=NULL;
    PFN_vkCreateBuffer createBuffer=NULL;
    PFN_vkGetBufferMemoryRequirements bufferRequirements=NULL;
    PFN_vkAllocateMemory allocate=NULL;
    PFN_vkBindBufferMemory bindBuffer=NULL;
    PFN_vkMapMemory mapMemory=NULL;
    PFN_vkCreateCommandPool createPool=NULL;
    PFN_vkAllocateCommandBuffers allocCommand=NULL;
    PFN_vkBeginCommandBuffer begin=NULL;
    PFN_vkEndCommandBuffer end=NULL;
    PFN_vkResetCommandBuffer resetCommand=NULL;
    PFN_vkCmdFillBuffer fillBuffer=NULL;
    PFN_vkCmdPipelineBarrier barrier=NULL;
    PFN_vkCreateFence createFence=NULL;
    PFN_vkResetFences resetFences=NULL;
    PFN_vkQueueSubmit submit=NULL;
    PFN_vkWaitForFences waitFences=NULL;
#define DEVICE_FN(dst,name) LOOKUP(dst,gdpa(device,name))
    DEVICE_FN(getQueue,"vkGetDeviceQueue");
    DEVICE_FN(createBuffer,"vkCreateBuffer");
    DEVICE_FN(bufferRequirements,"vkGetBufferMemoryRequirements");
    DEVICE_FN(allocate,"vkAllocateMemory");
    DEVICE_FN(bindBuffer,"vkBindBufferMemory");
    DEVICE_FN(mapMemory,"vkMapMemory");
    DEVICE_FN(createPool,"vkCreateCommandPool");
    DEVICE_FN(allocCommand,"vkAllocateCommandBuffers");
    DEVICE_FN(begin,"vkBeginCommandBuffer");
    DEVICE_FN(end,"vkEndCommandBuffer");
    DEVICE_FN(resetCommand,"vkResetCommandBuffer");
    DEVICE_FN(fillBuffer,"vkCmdFillBuffer");
    DEVICE_FN(barrier,"vkCmdPipelineBarrier");
    DEVICE_FN(createFence,"vkCreateFence");
    DEVICE_FN(resetFences,"vkResetFences");
    DEVICE_FN(submit,"vkQueueSubmit");
    DEVICE_FN(waitFences,"vkWaitForFences");
    DEVICE_FN(destroyBuffer,"vkDestroyBuffer");
    DEVICE_FN(freeMemory,"vkFreeMemory");
    DEVICE_FN(unmapMemory,"vkUnmapMemory");
    DEVICE_FN(destroyPool,"vkDestroyCommandPool");
    DEVICE_FN(destroyFence,"vkDestroyFence");
    DEVICE_FN(waitIdle,"vkDeviceWaitIdle");
    DEVICE_FN(destroyDevice,"vkDestroyDevice");
#undef DEVICE_FN
    getQueue(device,queueFamily,0,&queue);
    if(queue==VK_NULL_HANDLE){stage="NO_DEVICE_QUEUE";goto out;}
    VkBufferCreateInfo bi={.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .size=64,.usage=VK_BUFFER_USAGE_TRANSFER_DST_BIT,
        .sharingMode=VK_SHARING_MODE_EXCLUSIVE};
    VK_CALL(createBuffer(device,&bi,NULL,&buffer),"CREATE_GPU_BUFFER");
    VkMemoryRequirements req={0};
    bufferRequirements(device,buffer,&req);
    VkPhysicalDeviceMemoryProperties mem={0};
    getMemoryProperties(physical,&mem);
    uint32_t idx=UINT32_MAX;
    for(uint32_t i=0;i<mem.memoryTypeCount && i<32;i++){
        if((req.memoryTypeBits&(1u<<i))&&
          (mem.memoryTypes[i].propertyFlags &
           (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
          (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)){
          idx=i;break;
        }
    }
    if(idx==UINT32_MAX){stage="NO_COHERENT_STAGING_MEMORY";goto out;}
    VkMemoryAllocateInfo ai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
       .allocationSize=req.size,.memoryTypeIndex=idx};
    VK_CALL(allocate(device,&ai,NULL,&memory),"ALLOCATE_GPU_STAGING");
    VK_CALL(bindBuffer(device,buffer,memory,0),"BIND_GPU_STAGING");
    VK_CALL(mapMemory(device,memory,0,64,0,&mapped),"MAP_GPU_STAGING");
    memset(mapped,0,64);
    VkCommandPoolCreateInfo pci={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
       .flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,.queueFamilyIndex=queueFamily};
    VK_CALL(createPool(device,&pci,NULL,&pool),"CREATE_COMMAND_POOL");
    VkCommandBufferAllocateInfo ci={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
       .commandPool=pool,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=1};
    VK_CALL(allocCommand(device,&ci,&cmd),"ALLOC_COMMAND_BUFFER");
    VkFenceCreateInfo fi={.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VK_CALL(createFence(device,&fi,NULL,&fence),"CREATE_GPU_FENCE");

    /* This displays the verified GPU buffer value, not an image swapchain.
     * FORMAT_RGBA_8888 bytes are RGBA in memory on Android little-endian.
     * A fresh SurfaceView is used so locking is not mixed with a Vulkan queue. */
    stage="OPEN_ANDROID_NATIVE_WINDOW";
    window=ANativeWindow_fromSurface(env,surface);
    if(!window){stage="ANDROID_NATIVE_WINDOW_UNAVAILABLE";goto out;}
    lastWindowStatus=ANativeWindow_setBuffersGeometry(
        window,320,180,WINDOW_FORMAT_RGBA_8888);
    if(lastWindowStatus!=0){stage="ANDROID_SURFACE_GEOMETRY_FAILED";goto out;}

    int maxFrames=requested<6?6:(requested>24?24:requested);
    const uint32_t values[]={0xff0000ffu,0xff00ff00u,0xffff0000u};
    for(int i=0;i<maxFrames;i++){
        uint32_t expected=values[i%3];
        memset(mapped,0,64); /* reject unchanged stale GPU readback */
        VK_CALL(resetCommand(cmd,0),"RESET_GPU_COMMAND");
        VkCommandBufferBeginInfo beginInfo={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
           .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
        VK_CALL(begin(cmd,&beginInfo),"BEGIN_GPU_COMMAND");
        fillBuffer(cmd,buffer,0,64,expected);
        VkBufferMemoryBarrier memBarrier={.sType=VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
           .srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
           .dstAccessMask=VK_ACCESS_HOST_READ_BIT,
           .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
           .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
           .buffer=buffer,.offset=0,.size=64};
        barrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,
                0,0,NULL,1,&memBarrier,0,NULL);
        VK_CALL(end(cmd),"END_GPU_COMMAND");
        VK_CALL(resetFences(device,1,&fence),"RESET_GPU_FENCE");
        VkSubmitInfo submission={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
           .commandBufferCount=1,.pCommandBuffers=&cmd};
        VK_CALL(submit(queue,1,&submission,fence),"QUEUE_GPU_FILL");
        VK_CALL(waitFences(device,1,&fence,VK_TRUE,8000000000ULL),"WAIT_GPU_FENCE");
        const uint32_t *word=(const uint32_t *)mapped;
        for(int k=0;k<16;k++){
            if(word[k]!=expected){
                stage="GPU_BUFFER_READBACK_MISMATCH";
                rc=VK_ERROR_UNKNOWN;goto out;
            }
        }
        gpuMatches++;
        stage="ANDROID_SURFACE_CPU_LOCK";
        ANativeWindow_Buffer back={0};
        lastWindowStatus=ANativeWindow_lock(window,&back,NULL);
        if(lastWindowStatus!=0){stage="ANDROID_SURFACE_LOCK_FAILED";goto out;}
        if(!back.bits||back.stride<320||back.width<320||back.height<180||
                back.format!=WINDOW_FORMAT_RGBA_8888){
            stage="ANDROID_SURFACE_FORMAT_UNEXPECTED";
            (void)ANativeWindow_unlockAndPost(window);
            goto out;
        }
        for(int y=0;y<180;y++){
            uint32_t *row=(uint32_t *)back.bits+(size_t)y*back.stride;
            for(int x=0;x<320;x++)row[x]=word[0];
        }
        stage="ANDROID_SURFACE_CPU_POST";
        lastWindowStatus=ANativeWindow_unlockAndPost(window);
        if(lastWindowStatus!=0){stage="ANDROID_SURFACE_POST_FAILED";goto out;}
        everPosted=true;
        frames++;
        usleep(130000);
    }
    stage="GPU_BUFFER_COLOR_SURFACE_POSTED";
    rc=VK_SUCCESS;
out:
    if(device!=VK_NULL_HANDLE&&waitIdle)(void)waitIdle(device);
    if(fence!=VK_NULL_HANDLE&&destroyFence)destroyFence(device,fence,NULL);
    if(pool!=VK_NULL_HANDLE&&destroyPool)destroyPool(device,pool,NULL);
    if(mapped&&unmapMemory)unmapMemory(device,memory);
    if(memory!=VK_NULL_HANDLE&&freeMemory)freeMemory(device,memory,NULL);
    if(buffer!=VK_NULL_HANDLE&&destroyBuffer)destroyBuffer(device,buffer,NULL);
    if(device!=VK_NULL_HANDLE&&destroyDevice)destroyDevice(device,NULL);
    if(instance!=VK_NULL_HANDLE&&destroyInstance)destroyInstance(instance,NULL);
    if(window)ANativeWindow_release(window);
    if(library)dlclose(library);
    if(path)(*env)->ReleaseStringUTFChars(env,pathString,path);
    snprintf(report,sizeof(report),
       "{\"schema\":\"rm11.private-turnip-gpu-cpu-surface.v1\","
       "\"stage\":\"%s\",\"vk_result\":%d,"
       "\"gpu_vendor_id\":%u,\"gpu_device_id\":%u,"
       "\"gpu_readback_matches\":%u,\"android_surface_posted_frames\":%u,"
       "\"last_native_window_status\":%d,"
       "\"any_surface_posted\":%s,"
       "\"private_icd\":true,\"pixel_path\":\"GPU_BUFFER_READBACK_TO_CPU_ANATIVEWINDOW\","
       "\"vulkan_swapchain_proven\":false,\"wine_dxvk_proven\":false,"
       "\"game_engine_activated\":false,\"visual_pixel_proof\":\"USER_REQUIRED\"}",
       stage,(int)rc,vendor,deviceId,gpuMatches,frames,lastWindowStatus,
       everPosted?"true":"false");
    return (*env)->NewStringUTF(env,report);
}
