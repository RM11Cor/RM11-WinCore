/*
 * RM11 device-only diagnostic: call the exactly selected APK-native Turnip ICD
 * WITHOUT linking Android's system Vulkan loader or selecting an ICD globally.
 * SPDX-License-Identifier: MIT
 * No Wine / DXVK / games, no surface, no presentation. Isolated process only.
 */
#define _GNU_SOURCE
#include <jni.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef PFN_vkVoidFunction (*rm11_icd_gpa_fn)(VkInstance,const char *);
typedef VkResult (*rm11_icd_negotiate_fn)(uint32_t *);

#define RESERVE_REPORT 1700
#define LOAD_FN(var, expression) do {                       \
    PFN_vkVoidFunction tmp_pointer = (expression);          \
    memcpy(&(var), &tmp_pointer, sizeof(var));                \
} while(0)

/* No device names or raw private paths exposed to the diagnostic report. */
JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RM11TurnipIcdProbe_nativeInspect(
        JNIEnv *env,jclass unused,jstring driver_path) {
    (void)unused;
    char json[RESERVE_REPORT];
    const char *path=NULL;
    void *library=NULL;
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    PFN_vkDestroyInstance destroy_instance=NULL;
    PFN_vkDestroyDevice destroy_device=NULL;
    int negotiated=-1, created=-999, enumerated=-999, logical=-999;
    uint32_t count=0, api=0, vendor=0, device_id=0, graphics=0, icd_version=7;
    const char *step="START";
    if (!driver_path) goto report;
    path=(*env)->GetStringUTFChars(env,driver_path,NULL);
    if(!path) goto report;
    /* The Java-side signed APK manifest validates this file's SHA256.
     * Native limits prevent using this function as a generic driver runner. */
    size_t length=strnlen(path,4096);
    const char *suffix="/libvulkan_freedreno.so";
    size_t suffixlen=strlen(suffix);
    if(length>=4096 || length<=suffixlen ||
       strcmp(path+length-suffixlen,suffix)!=0 ||
       strncmp(path,"/data/app/",10)!=0 ||
       strstr(path,"/../")!=NULL || strstr(path,"//")!=NULL) {
        step="REJECT_UNTRUSTED_DRIVER_PATH";
        goto report;
    }
    step="ICD_DLOPEN";
    library=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!library){step="ICD_DLOPEN_FAILED";goto report;}

    /* POSIX dlsym handles are ABI-wide pointers on Android arm64. */
    rm11_icd_gpa_fn gpa=NULL;
    rm11_icd_negotiate_fn negotiate=NULL;
    void *symbol=dlsym(library,"vk_icdGetInstanceProcAddr");
    if(!symbol || sizeof(gpa)!=sizeof(symbol)){
        step="ICD_ENTRYPOINT_MISSING";goto report;
    }
    memcpy(&gpa,&symbol,sizeof(gpa));
    symbol=dlsym(library,"vk_icdNegotiateLoaderICDInterfaceVersion");
    if(symbol && sizeof(negotiate)==sizeof(symbol)){
        memcpy(&negotiate,&symbol,sizeof(negotiate));
        negotiated=negotiate(&icd_version);
        if(negotiated!=VK_SUCCESS || icd_version<1){
            step="ICD_INTERFACE_NEGOTIATION_FAILED";goto report;
        }
    }else{
        icd_version=1;
    }
    PFN_vkCreateInstance create_instance=NULL;
    LOAD_FN(create_instance,gpa(VK_NULL_HANDLE,"vkCreateInstance"));
    if(!create_instance){step="VK_CREATE_INSTANCE_SYMBOL_MISSING";goto report;}
    const VkApplicationInfo info={
        .sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName="RM11-Isolated-ICD-Device-Probe",
        .applicationVersion=1,
        .pEngineName="RM11-Diagnostic-Only",
        .engineVersion=1,
        .apiVersion=VK_API_VERSION_1_1
    };
    const VkInstanceCreateInfo ci={
        .sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo=&info,
    };
    step="VK_CREATE_INSTANCE";
    created=create_instance(&ci,NULL,&instance);
    if(created!=VK_SUCCESS || instance==VK_NULL_HANDLE)goto report;
    LOAD_FN(destroy_instance,gpa(instance,"vkDestroyInstance"));
    PFN_vkEnumeratePhysicalDevices enumerate=NULL;
    LOAD_FN(enumerate,gpa(instance,"vkEnumeratePhysicalDevices"));
    if(!enumerate){step="VK_ENUMERATE_SYMBOL_MISSING";goto cleanup;}
    step="VK_ENUMERATE_PHYSICAL_DEVICES";
    enumerated=enumerate(instance,&count,NULL);
    if(enumerated!=VK_SUCCESS || !count || count>32)goto cleanup;
    /* One handle is sufficient: never invent device support based on counts. */
    VkPhysicalDevice phys[32]={0};
    uint32_t capacity=count;
    enumerated=enumerate(instance,&capacity,phys);
    if((enumerated!=VK_SUCCESS && enumerated!=VK_INCOMPLETE) || capacity==0)
        goto cleanup;
    count=capacity;
    PFN_vkGetPhysicalDeviceProperties properties=NULL;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties queues=NULL;
    PFN_vkCreateDevice create_device=NULL;
    LOAD_FN(properties,gpa(instance,"vkGetPhysicalDeviceProperties"));
    LOAD_FN(queues,gpa(instance,"vkGetPhysicalDeviceQueueFamilyProperties"));
    LOAD_FN(create_device,gpa(instance,"vkCreateDevice"));
    if(!properties || !queues || !create_device){
        step="VK_DEVICE_SYMBOLS_MISSING";goto cleanup;
    }
    VkPhysicalDeviceProperties props;
    memset(&props,0,sizeof(props));
    properties(phys[0],&props);
    vendor=props.vendorID;
    device_id=props.deviceID;
    api=props.apiVersion;
    uint32_t family_count=0;
    queues(phys[0],&family_count,NULL);
    if(!family_count || family_count>128){
        step="VK_GRAPHICS_QUEUE_UNAVAILABLE";goto cleanup;
    }
    VkQueueFamilyProperties families[128];
    memset(families,0,sizeof(families));
    queues(phys[0],&family_count,families);
    uint32_t index=UINT32_MAX;
    for(uint32_t i=0;i<family_count;i++){
        if((families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) &&
           families[i].queueCount>0){index=i;graphics=1;break;}
    }
    if(index==UINT32_MAX){step="VK_GRAPHICS_QUEUE_UNAVAILABLE";goto cleanup;}
    float priority=1.0f;
    const VkDeviceQueueCreateInfo queue_info={
        .sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex=index,.queueCount=1,.pQueuePriorities=&priority
    };
    const VkDeviceCreateInfo device_info={
        .sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount=1,.pQueueCreateInfos=&queue_info
    };
    step="VK_CREATE_LOGICAL_DEVICE";
    logical=create_device(phys[0],&device_info,NULL,&device);
    if(logical==VK_SUCCESS && device!=VK_NULL_HANDLE){
        LOAD_FN(destroy_device,gpa(instance,"vkDestroyDevice"));
        step="VK_LOGICAL_DEVICE_CREATED";
    }
cleanup:
    if(device!=VK_NULL_HANDLE && destroy_device)destroy_device(device,NULL);
    if(instance!=VK_NULL_HANDLE && destroy_instance)destroy_instance(instance,NULL);
report:
    /* Path intentionally excluded; these fields are READ-ONLY evidence. */
    snprintf(json,sizeof(json),
       "{\"schema\":\"rm11.turnip-icd-device.v1\",\"stage\":\"%s\","
       "\"icd_negotiate_result\":%d,\"icd_interface_version\":%u,"
       "\"vk_create_instance\":%d,\"vk_enumerate_physical_devices\":%d,"
       "\"physical_device_count\":%u,\"vendor_id\":%u,\"device_id\":%u,"
       "\"api_version\":%u,\"graphics_queue_present\":%s,"
       "\"vk_create_logical_device\":%d,"
       "\"hardware_frame_proof\":false,\"x11_swapchain_tested\":false,"
       "\"wine_dxvk_tested\":false,\"game_activation\":false}",
       step,negotiated,icd_version,created,enumerated,count,
       vendor,device_id,api,graphics?"true":"false",logical);
    if(library)dlclose(library);
    if(path)(*env)->ReleaseStringUTFChars(env,driver_path,path);
    return (*env)->NewStringUTF(env,json);
}
