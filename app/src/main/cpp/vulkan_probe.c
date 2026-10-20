/* RM11-WinCore — real, read-only Vulkan 1.0 smoke probe.
 * JNI queries the Android Vulkan loader; creates/destroys one logical device,
 * without shader execution, rendering, file access, game execution or networking.
 */
#include <jni.h>
#include <vulkan/vulkan.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

static char buffer[16384];
static size_t used;

static void append(const char *fmt, ...) {
    if (used >= sizeof(buffer)) return;
    va_list ap;
    va_start(ap,fmt);
    int n=vsnprintf(buffer+used,sizeof(buffer)-used,fmt,ap);
    va_end(ap);
    if (n<0) return;
    if ((size_t)n>=sizeof(buffer)-used) used=sizeof(buffer)-1;
    else used+=(size_t)n;
}
static void json_string(const char *s) {
    append("\"");
    if (s) for (const unsigned char *p=(const unsigned char *)s; *p; p++) {
        /* Driver name is normally ASCII. Avoid malformed UTF-8 and JSON escapes. */
        if (*p=='"'||*p=='\\') append("\\%c",*p);
        else if (*p>=32 && *p<127) append("%c",*p);
        else if (*p>=128) append("?");
    }
    append("\"");
}
static const char *kind(VkPhysicalDeviceType t) {
    switch(t) {case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU:return "integrated";
      case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:return "discrete";
      case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU:return "virtual";
      case VK_PHYSICAL_DEVICE_TYPE_CPU:return "cpu";
      default:return "other";}
}
static int extension_present(const VkExtensionProperties *p, uint32_t count,const char *name) {
    for(uint32_t i=0;i<count;i++) if(strcmp(p[i].extensionName,name)==0) return 1;
    return 0;
}
JNIEXPORT jstring JNICALL Java_com_rm11_autocore_VulkanNativeProbe_nativeProbe(JNIEnv *env, jclass klass) {
    (void)klass;
    used=0;
    buffer[0]='\0';
    VkApplicationInfo app={0};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="RM11 AutoCore GPU Probe";
    app.applicationVersion=1;
    app.pEngineName="RM11 Vulkan Diagnostics";
    app.engineVersion=1;
    app.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo ci={0};
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo=&app;
    VkInstance instance=VK_NULL_HANDLE;
    VkResult ret=vkCreateInstance(&ci,NULL,&instance);
    if (ret!=VK_SUCCESS) {
        append("{\"status\":\"instance_failed\",\"vkResult\":%d,\"instanceCreated\":false,\"physicalDeviceCount\":0,\"devices\":[]}",(int)ret);
        return (*env)->NewStringUTF(env,buffer);
    }
    uint32_t count=0;
    ret=vkEnumeratePhysicalDevices(instance,&count,NULL);
    if (ret!=VK_SUCCESS || count==0) {
        append("{\"status\":\"no_physical_device\",\"vkResult\":%d,\"instanceCreated\":true,\"physicalDeviceCount\":0,\"devices\":[]}",(int)ret);
        vkDestroyInstance(instance,NULL);
        return (*env)->NewStringUTF(env,buffer);
    }
    /* Cap enumeration for bounded memory and output; usually exactly 1 GPU on phones. */
    uint32_t sample=count>4?4:count;
    VkPhysicalDevice physical[4]={0};
    uint32_t requested=sample;
    ret=vkEnumeratePhysicalDevices(instance,&requested,physical);
    if (ret!=VK_SUCCESS && ret!=VK_INCOMPLETE) {
        append("{\"status\":\"enumeration_failed\",\"vkResult\":%d,\"instanceCreated\":true,\"physicalDeviceCount\":%u,\"devices\":[]}",(int)ret,(unsigned)count);
        vkDestroyInstance(instance,NULL);
        return (*env)->NewStringUTF(env,buffer);
    }
    append("{\"status\":\"enumerated\",\"instanceCreated\":true,\"physicalDeviceCount\":%u,\"devices\":[",(unsigned)count);
    for(uint32_t i=0;i<requested;i++) {
        if(i) append(",");
        VkPhysicalDeviceProperties props={0};
        vkGetPhysicalDeviceProperties(physical[i],&props);
        uint32_t queueCount=0;
        vkGetPhysicalDeviceQueueFamilyProperties(physical[i],&queueCount,NULL);
        uint32_t graphics=0,compute=0,graphicsFamily=UINT32_MAX;
        VkQueueFamilyProperties qprops[32];
        if(queueCount>0) {
            uint32_t usedQueues=queueCount>32?32:queueCount;
            vkGetPhysicalDeviceQueueFamilyProperties(physical[i],&usedQueues,qprops);
            for(uint32_t j=0;j<usedQueues;j++) {
                if(qprops[j].queueCount && (qprops[j].queueFlags&VK_QUEUE_GRAPHICS_BIT)) {
                    graphics++; if(graphicsFamily==UINT32_MAX) graphicsFamily=j;
                }
                if(qprops[j].queueCount && (qprops[j].queueFlags&VK_QUEUE_COMPUTE_BIT)) compute++;
            }
        }
        uint32_t extCount=0;
        VkExtensionProperties exts[512];
        int hasSwapchain=0,hasTimeline=0,hasRay=0,hasAcceleration=0;
        VkResult extRet=vkEnumerateDeviceExtensionProperties(physical[i],NULL,&extCount,NULL);
        if(extRet==VK_SUCCESS && extCount>0) {
            uint32_t sampled=extCount>512?512:extCount;
            extRet=vkEnumerateDeviceExtensionProperties(physical[i],NULL,&sampled,exts);
            if(extRet==VK_SUCCESS || extRet==VK_INCOMPLETE) {
                hasSwapchain=extension_present(exts,sampled,"VK_KHR_swapchain");
                hasTimeline=extension_present(exts,sampled,"VK_KHR_timeline_semaphore");
                hasRay=extension_present(exts,sampled,"VK_KHR_ray_tracing_pipeline");
                hasAcceleration=extension_present(exts,sampled,"VK_KHR_acceleration_structure");
            }
        }
        VkResult deviceResult=VK_ERROR_INITIALIZATION_FAILED;
        if(graphicsFamily!=UINT32_MAX) {
            float priority=1.0f;
            VkDeviceQueueCreateInfo qci={0};
            qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
            qci.queueFamilyIndex=graphicsFamily;
            qci.queueCount=1;
            qci.pQueuePriorities=&priority;
            VkDeviceCreateInfo dci={0};
            dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
            dci.queueCreateInfoCount=1;
            dci.pQueueCreateInfos=&qci;
            VkDevice device=VK_NULL_HANDLE;
            deviceResult=vkCreateDevice(physical[i],&dci,NULL,&device);
            if(deviceResult==VK_SUCCESS && device!=VK_NULL_HANDLE) vkDestroyDevice(device,NULL);
        }
        append("{\"name\":");json_string(props.deviceName);
        append(",\"apiVersion\":\"%u.%u.%u\",\"vendorId\":%u,\"deviceId\":%u,\"driverVersionRaw\":%u,\"type\":\"%s\",\"graphicsQueueFamilies\":%u,\"computeQueueFamilies\":%u,\"swapchainExtension\":%s,\"timelineSemaphoreExtension\":%s,\"rayTracingPipelineExtension\":%s,\"accelerationStructureExtension\":%s,\"logicalDeviceCreateResult\":%d}",
         (unsigned)VK_VERSION_MAJOR(props.apiVersion),(unsigned)VK_VERSION_MINOR(props.apiVersion),(unsigned)VK_VERSION_PATCH(props.apiVersion),
         (unsigned)props.vendorID,(unsigned)props.deviceID,(unsigned)props.driverVersion,kind(props.deviceType),
         (unsigned)graphics,(unsigned)compute,hasSwapchain?"true":"false",hasTimeline?"true":"false",hasRay?"true":"false",hasAcceleration?"true":"false",(int)deviceResult);
    }
    append("]}");
    vkDestroyInstance(instance,NULL);
    return (*env)->NewStringUTF(env,buffer);
}
