/*
 * RM11 v4.90.3 — isolated private Turnip ICD GPU command/readback proof.
 * This cannot establish Android display, X11 WSI, Wine or DXVK operation.
 * No loader/global environment mutation; no application/game data writes.
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include <jni.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef PFN_vkVoidFunction (*icd_get_instance_proc)(VkInstance,const char *);
typedef VkResult (*icd_negotiate)(uint32_t *);
#define GET_PROC(out, expr) do { \
    PFN_vkVoidFunction raw_ptr=(expr); \
    memcpy(&(out), &raw_ptr, sizeof(out)); \
} while(0)

/* Each name below resolves from the correct signed private ICD, never
 * Android /system/lib64/libvulkan.so. */
static VkResult submit_verified_fill(icd_get_instance_proc gpa,
     VkInstance instance, VkPhysicalDevice phys, VkDevice device,
     uint32_t graphics_family, const char **stage, int *submitted,
     int *waited, int *readback_match) {
    const uint32_t MAGIC=0x59a7ce32u;
    VkResult res=VK_ERROR_INITIALIZATION_FAILED;
    PFN_vkGetDeviceProcAddr gdpa=NULL;
    PFN_vkGetPhysicalDeviceMemoryProperties getmem=NULL;
    GET_PROC(gdpa,gpa(instance,"vkGetDeviceProcAddr"));
    GET_PROC(getmem,gpa(instance,"vkGetPhysicalDeviceMemoryProperties"));
    if(!gdpa || !getmem){*stage="ICD_DEVICE_PROC_MISSING";return res;}

    PFN_vkGetDeviceQueue getqueue=NULL;
    PFN_vkCreateBuffer mkbuffer=NULL;
    PFN_vkDestroyBuffer delbuffer=NULL;
    PFN_vkGetBufferMemoryRequirements memreq=NULL;
    PFN_vkAllocateMemory allocmem=NULL;
    PFN_vkFreeMemory freemem=NULL;
    PFN_vkBindBufferMemory bindmem=NULL;
    PFN_vkMapMemory mapmem=NULL;
    PFN_vkUnmapMemory unmapmem=NULL;
    PFN_vkCreateCommandPool mkpool=NULL;
    PFN_vkDestroyCommandPool delpool=NULL;
    PFN_vkAllocateCommandBuffers alloccmd=NULL;
    PFN_vkBeginCommandBuffer begincmd=NULL;
    PFN_vkCmdFillBuffer fillcmd=NULL;
    PFN_vkEndCommandBuffer endcmd=NULL;
    PFN_vkCreateFence mkfence=NULL;
    PFN_vkDestroyFence delfence=NULL;
    PFN_vkQueueSubmit submit=NULL;
    PFN_vkWaitForFences wait=NULL;
#define LOAD_DEVICE(f,n) GET_PROC(f,gdpa(device,n))
    LOAD_DEVICE(getqueue,"vkGetDeviceQueue");
    LOAD_DEVICE(mkbuffer,"vkCreateBuffer");
    LOAD_DEVICE(delbuffer,"vkDestroyBuffer");
    LOAD_DEVICE(memreq,"vkGetBufferMemoryRequirements");
    LOAD_DEVICE(allocmem,"vkAllocateMemory");
    LOAD_DEVICE(freemem,"vkFreeMemory");
    LOAD_DEVICE(bindmem,"vkBindBufferMemory");
    LOAD_DEVICE(mapmem,"vkMapMemory");
    LOAD_DEVICE(unmapmem,"vkUnmapMemory");
    LOAD_DEVICE(mkpool,"vkCreateCommandPool");
    LOAD_DEVICE(delpool,"vkDestroyCommandPool");
    LOAD_DEVICE(alloccmd,"vkAllocateCommandBuffers");
    LOAD_DEVICE(begincmd,"vkBeginCommandBuffer");
    LOAD_DEVICE(fillcmd,"vkCmdFillBuffer");
    LOAD_DEVICE(endcmd,"vkEndCommandBuffer");
    LOAD_DEVICE(mkfence,"vkCreateFence");
    LOAD_DEVICE(delfence,"vkDestroyFence");
    LOAD_DEVICE(submit,"vkQueueSubmit");
    LOAD_DEVICE(wait,"vkWaitForFences");
#undef LOAD_DEVICE
    if(!getqueue||!mkbuffer||!delbuffer||!memreq||!allocmem||!freemem||
       !bindmem||!mapmem||!unmapmem||!mkpool||!delpool||!alloccmd||
       !begincmd||!fillcmd||!endcmd||!mkfence||!delfence||!submit||!wait){
        *stage="ICD_QUEUE_FUNCTIONS_MISSING";return res;
    }

    VkBuffer buffer=VK_NULL_HANDLE;
    VkDeviceMemory memory=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    VkQueue queue=VK_NULL_HANDLE;
    void *mapped=NULL;

    *stage="GPU_CREATE_TRANSFER_BUFFER";
    VkBufferCreateInfo buf={0};
    buf.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buf.size=64;
    buf.usage=VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    buf.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    res=mkbuffer(device,&buf,NULL,&buffer);
    if(res!=VK_SUCCESS)goto finish;
    VkMemoryRequirements requirements;
    memreq(device,buffer,&requirements);
    VkPhysicalDeviceMemoryProperties mp;
    memset(&mp,0,sizeof(mp));
    getmem(phys,&mp);
    uint32_t memory_index=UINT32_MAX;
    for(uint32_t i=0;i<mp.memoryTypeCount && i<32;i++){
        if((requirements.memoryTypeBits & (1u<<i)) &&
           (mp.memoryTypes[i].propertyFlags &
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)){
            memory_index=i;
            break;
        }
    }
    if(memory_index==UINT32_MAX){
        *stage="GPU_NO_HOST_COHERENT_MEMORY";
        res=VK_ERROR_FEATURE_NOT_PRESENT;
        goto finish;
    }
    *stage="GPU_ALLOCATE_COHERENT_MEMORY";
    VkMemoryAllocateInfo memory_info={0};
    memory_info.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    memory_info.allocationSize=requirements.size;
    memory_info.memoryTypeIndex=memory_index;
    res=allocmem(device,&memory_info,NULL,&memory);
    if(res!=VK_SUCCESS)goto finish;
    res=bindmem(device,buffer,memory,0);
    if(res!=VK_SUCCESS)goto finish;
    res=mapmem(device,memory,0,64,0,&mapped);
    if(res!=VK_SUCCESS)goto finish;
    memset(mapped,0,64);

    *stage="GPU_RECORD_FILL_COMMAND";
    VkCommandPoolCreateInfo pool_info={0};
    pool_info.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_info.queueFamilyIndex=graphics_family;
    res=mkpool(device,&pool_info,NULL,&pool);
    if(res!=VK_SUCCESS)goto finish;
    VkCommandBufferAllocateInfo cmd_info={0};
    cmd_info.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmd_info.commandPool=pool;
    cmd_info.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cmd_info.commandBufferCount=1;
    res=alloccmd(device,&cmd_info,&cmd);
    if(res!=VK_SUCCESS)goto finish;
    VkCommandBufferBeginInfo begin_info={0};
    begin_info.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    res=begincmd(cmd,&begin_info);
    if(res!=VK_SUCCESS)goto finish;
    fillcmd(cmd,buffer,0,64,MAGIC);
    /* Make transfer writes visible to HOST access after the completion fence. */
    PFN_vkCmdPipelineBarrier barrier=NULL;
    GET_PROC(barrier,gdpa(device,"vkCmdPipelineBarrier"));
    if(!barrier){*stage="GPU_BARRIER_SYMBOL_MISSING";goto finish;}
    VkBufferMemoryBarrier memory_barrier={0};
    memory_barrier.sType=VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    memory_barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    memory_barrier.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    memory_barrier.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    memory_barrier.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    memory_barrier.buffer=buffer;
    memory_barrier.offset=0;
    memory_barrier.size=64;
    barrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,
            0,0,NULL,1,&memory_barrier,0,NULL);
    res=endcmd(cmd);
    if(res!=VK_SUCCESS)goto finish;
    VkFenceCreateInfo fence_info={0};
    fence_info.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    res=mkfence(device,&fence_info,NULL,&fence);
    if(res!=VK_SUCCESS)goto finish;
    getqueue(device,graphics_family,0,&queue);
    if(queue==VK_NULL_HANDLE){
        *stage="GPU_QUEUE_NULL";
        res=VK_ERROR_INITIALIZATION_FAILED;
        goto finish;
    }
    VkSubmitInfo submit_info={0};
    submit_info.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit_info.commandBufferCount=1;
    submit_info.pCommandBuffers=&cmd;
    *stage="GPU_QUEUE_SUBMIT";
    res=submit(queue,1,&submit_info,fence);
    if(res!=VK_SUCCESS)goto finish;
    *submitted=1;
    *stage="GPU_WAIT_FENCE";
    res=wait(device,1,&fence,VK_TRUE,8000000000ULL);
    if(res!=VK_SUCCESS)goto finish;
    *waited=1;
    *stage="GPU_VALIDATE_READBACK";
    const uint32_t *values=(const uint32_t *)mapped;
    *readback_match=1;
    for(size_t i=0;i<16;i++){
        if(values[i]!=MAGIC){*readback_match=0;break;}
    }
    if(!*readback_match){
        res=VK_ERROR_UNKNOWN;
        *stage="GPU_READBACK_WRONG_VALUE";
    }else{
        res=VK_SUCCESS;
        *stage="GPU_TRANSFER_READBACK_MATCH";
    }
finish:
    /* Only valid GPU handles are destroyed, in reverse dependency order. */
    if(fence!=VK_NULL_HANDLE)delfence(device,fence,NULL);
    if(pool!=VK_NULL_HANDLE)delpool(device,pool,NULL);
    if(mapped)unmapmem(device,memory);
    if(memory!=VK_NULL_HANDLE)freemem(device,memory,NULL);
    if(buffer!=VK_NULL_HANDLE)delbuffer(device,buffer,NULL);
    return res;
}

JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RM11TurnipGpuProof_nativeRun(
     JNIEnv *env,jclass unused,jstring signed_path){
    (void)unused;
    char response[1200];
    const char *step="START";
    const char *path=NULL;
    void *lib=NULL;
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    PFN_vkDestroyInstance delinstance=NULL;
    PFN_vkDestroyDevice deldevice=NULL;
    int instance_result=-999,device_result=-999,queue_result=-999;
    int submitted=0,waited=0,match=0;
    uint32_t vendor=0,device_id=0;
    if(!signed_path)goto report;
    path=(*env)->GetStringUTFChars(env,signed_path,NULL);
    if(!path)goto report;
    const size_t n=strnlen(path,4096);
    const char suffix[]="/libvulkan_freedreno.so";
    if(n>=4096||n<=sizeof(suffix)-1||
        strcmp(path+n-(sizeof(suffix)-1),suffix)!=0||
        strncmp(path,"/data/app/",10)!=0||
        strstr(path,"/../")||strstr(path,"//")){
        step="UNTRUSTED_SIGNED_PATH";goto report;
    }
    step="ICD_DLOPEN";
    lib=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!lib){step="ICD_DLOPEN_FAILED";goto report;}
    icd_get_instance_proc gpa=NULL;
    void *raw=dlsym(lib,"vk_icdGetInstanceProcAddr");
    if(!raw||sizeof(gpa)!=sizeof(raw)){
        step="ICD_GPA_MISSING";goto report;
    }
    memcpy(&gpa,&raw,sizeof(gpa));
    icd_negotiate negotiate=NULL;
    raw=dlsym(lib,"vk_icdNegotiateLoaderICDInterfaceVersion");
    if(raw&&sizeof(negotiate)==sizeof(raw)){
        memcpy(&negotiate,&raw,sizeof(negotiate));
        uint32_t version=7;
        if(negotiate(&version)!=VK_SUCCESS || version<1){
            step="ICD_NEGOTIATION_FAILED";goto report;
        }
    }
    PFN_vkCreateInstance create_instance=NULL;
    GET_PROC(create_instance,gpa(VK_NULL_HANDLE,"vkCreateInstance"));
    if(!create_instance){step="CREATE_INSTANCE_MISSING";goto report;}
    VkApplicationInfo info={0};
    info.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    info.pApplicationName="RM11-GPU-Command-Test";
    info.apiVersion=VK_API_VERSION_1_1;
    VkInstanceCreateInfo instance_info={0};
    instance_info.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instance_info.pApplicationInfo=&info;
    step="CREATE_INSTANCE";
    instance_result=create_instance(&instance_info,NULL,&instance);
    if(instance_result!=VK_SUCCESS||instance==VK_NULL_HANDLE)goto cleanup;
    GET_PROC(delinstance,gpa(instance,"vkDestroyInstance"));
    PFN_vkEnumeratePhysicalDevices enumerate=NULL;
    PFN_vkGetPhysicalDeviceProperties getprop=NULL;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties getfamilies=NULL;
    PFN_vkCreateDevice create_device=NULL;
    GET_PROC(enumerate,gpa(instance,"vkEnumeratePhysicalDevices"));
    GET_PROC(getprop,gpa(instance,"vkGetPhysicalDeviceProperties"));
    GET_PROC(getfamilies,gpa(instance,"vkGetPhysicalDeviceQueueFamilyProperties"));
    GET_PROC(create_device,gpa(instance,"vkCreateDevice"));
    if(!enumerate||!getprop||!getfamilies||!create_device){
        step="INSTANCE_FUNCTION_MISSING";goto cleanup;
    }
    uint32_t count=0;
    step="ENUMERATE_PHYSICAL_DEVICE";
    if(enumerate(instance,&count,NULL)!=VK_SUCCESS||count==0||count>16)
        goto cleanup;
    VkPhysicalDevice physicals[16]={0};
    uint32_t capacity=count;
    if(enumerate(instance,&capacity,physicals)!=VK_SUCCESS||capacity==0)
        goto cleanup;
    VkPhysicalDeviceProperties props;
    getprop(physicals[0],&props);
    vendor=props.vendorID;device_id=props.deviceID;
    uint32_t family_count=0;
    getfamilies(physicals[0],&family_count,NULL);
    if(family_count==0||family_count>128){
        step="GRAPHICS_QUEUE_UNAVAILABLE";goto cleanup;
    }
    VkQueueFamilyProperties families[128]={0};
    getfamilies(physicals[0],&family_count,families);
    uint32_t selected=UINT32_MAX;
    for(uint32_t i=0;i<family_count;i++){
        if(families[i].queueCount>0 &&
           (families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)){
            selected=i;break;
        }
    }
    if(selected==UINT32_MAX){step="GRAPHICS_QUEUE_UNAVAILABLE";goto cleanup;}
    float priority=1.0f;
    VkDeviceQueueCreateInfo qinfo={0};
    qinfo.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qinfo.queueFamilyIndex=selected;
    qinfo.queueCount=1;qinfo.pQueuePriorities=&priority;
    VkDeviceCreateInfo dinfo={0};
    dinfo.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dinfo.queueCreateInfoCount=1;dinfo.pQueueCreateInfos=&qinfo;
    step="CREATE_DEVICE";
    device_result=create_device(physicals[0],&dinfo,NULL,&device);
    if(device_result!=VK_SUCCESS||device==VK_NULL_HANDLE)goto cleanup;
    GET_PROC(deldevice,gpa(instance,"vkDestroyDevice"));
    step="SUBMIT_GPU_TRANSFER";
    queue_result=submit_verified_fill(gpa,instance,physicals[0],device,
        selected,&step,&submitted,&waited,&match);
cleanup:
    if(device!=VK_NULL_HANDLE&&deldevice)deldevice(device,NULL);
    if(instance!=VK_NULL_HANDLE&&delinstance)delinstance(instance,NULL);
report:
    snprintf(response,sizeof(response),
      "{\"schema\":\"rm11.turnip-gpu-transfer.v1\","
      "\"stage\":\"%s\",\"instance_result\":%d,\"device_result\":%d,"
      "\"queue_result\":%d,\"vendor_id\":%u,\"device_id\":%u,"
      "\"queue_submit_success\":%s,\"fence_completed\":%s,"
      "\"gpu_buffer_readback_match\":%s,"
      "\"android_display_frame_proven\":false,\"wine_dxvk_proven\":false,"
      "\"x11_swapchain_proven\":false,\"game_engine_activated\":false}",
      step,instance_result,device_result,queue_result,vendor,device_id,
      submitted?"true":"false",waited?"true":"false",match?"true":"false");
    if(lib)dlclose(lib);
    if(path)(*env)->ReleaseStringUTFChars(env,signed_path,path);
    return (*env)->NewStringUTF(env,response);
}
