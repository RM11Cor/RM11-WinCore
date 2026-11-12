// Original independent test code. Does NOT load PC CarX binaries/assets.
#include <jni.h>
#include <vulkan/vulkan.h>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {
std::string jsonQuote(const char* s) {
    if (!s) return "\"\"";
    std::ostringstream o;
    o << '"';
    for (size_t i=0; s[i] && i<256; ++i) {
        unsigned char ch=static_cast<unsigned char>(s[i]);
        switch(ch) {
            case '"': o<<"\\\""; break;
            case '\\': o<<"\\\\"; break;
            case '\n': o<<"\\n"; break;
            case '\r': o<<"\\r"; break;
            case '\t': o<<"\\t"; break;
            default:
                if (ch < 32 || ch > 126) {
                    static const char* k="0123456789abcdef";
                    o<<"\\u00"<<k[ch>>4]<<k[ch&15];
                } else o<<static_cast<char>(ch);
        }
    }
    o << '"';
    return o.str();
}
std::string apiVersion(uint32_t x) {
    std::ostringstream out;
    out << VK_VERSION_MAJOR(x)<<"."<<VK_VERSION_MINOR(x)<<"."<<VK_VERSION_PATCH(x);
    return out.str();
}
std::string nativeReport() {
    std::ostringstream out;
    out<<"{";
#if defined(__aarch64__)
    out<<"\"compiled_abi\":\"arm64-v8a\",\"native_arm64_procedure_executed\":true,";
#else
    out<<"\"compiled_abi\":\"unsupported\",\"native_arm64_procedure_executed\":false,";
#endif
    out<<"\"original_carx_game_code_executed\":false,";
    out<<"\"game_frame_rendered\":false,";
    out<<"\"actual_vulkan_surface_created\":false,";
    out<<"\"actual_vulkan_swapchain_created\":false,";
    out<<"\"vk_instance_api_request\":\"1.0\",";
    VkApplicationInfo appInfo{};
    appInfo.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName="CarX PortLab ARM64 Vulkan preflight ONLY";
    appInfo.applicationVersion=VK_MAKE_VERSION(0,5,0);
    appInfo.pEngineName="PortLab independent bootstrap, not CarX engine";
    appInfo.engineVersion=VK_MAKE_VERSION(0,5,0);
    appInfo.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo ci{};
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo=&appInfo;
    VkInstance instance=VK_NULL_HANDLE;
    VkResult createResult=vkCreateInstance(&ci,nullptr,&instance);
    out<<"\"vk_create_instance_result\":"<<static_cast<int>(createResult)<<",";
    bool created=(createResult==VK_SUCCESS && instance!=VK_NULL_HANDLE);
    out<<"\"vulkan_instance_created\":"<<(created?"true":"false")<<",";
    uint32_t count=0;
    if (created) {
        VkResult enumerate=vkEnumeratePhysicalDevices(instance,&count,nullptr);
        out<<"\"physical_device_enumeration_result\":"<<static_cast<int>(enumerate)<<",";
        if (enumerate!=VK_SUCCESS || count>16) count=0;
    } else {
        out<<"\"physical_device_enumeration_result\":null,";
    }
    out<<"\"physical_device_count\":"<<count<<",";
    if (created && count>0) {
        std::vector<VkPhysicalDevice> devices(count);
        uint32_t requested=count;
        VkResult listing=vkEnumeratePhysicalDevices(instance,&requested,devices.data());
        if (listing==VK_SUCCESS && requested>0 && requested<=count) {
            VkPhysicalDeviceProperties props{};
            vkGetPhysicalDeviceProperties(devices[0],&props);
            out<<"\"gpu_name\":"<<jsonQuote(props.deviceName)<<",";
            out<<"\"gpu_vendor_id\":"<<props.vendorID<<",";
            out<<"\"gpu_device_id\":"<<props.deviceID<<",";
            out<<"\"gpu_driver_version_raw\":"<<props.driverVersion<<",";
            out<<"\"gpu_vulkan_api_version\":"<<jsonQuote(apiVersion(props.apiVersion).c_str())<<",";
            out<<"\"gpu_max_image_dimension_2d\":"<<props.limits.maxImageDimension2D<<",";
            VkPhysicalDeviceMemoryProperties memory{};
            vkGetPhysicalDeviceMemoryProperties(devices[0],&memory);
            uint64_t biggestLocalHeap=0;
            for(uint32_t i=0;i<memory.memoryHeapCount;i++) {
                if((memory.memoryHeaps[i].flags&VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)!=0 &&
                    memory.memoryHeaps[i].size>biggestLocalHeap) {
                    biggestLocalHeap=memory.memoryHeaps[i].size;
                }
            }
            out<<"\"biggest_device_local_heap_bytes\":"<<biggestLocalHeap<<",";
            uint32_t extCount=0;
            bool hasSwapchain=false;
            if(vkEnumerateDeviceExtensionProperties(devices[0],nullptr,&extCount,nullptr)==VK_SUCCESS &&
               extCount>0 && extCount<10000) {
                std::vector<VkExtensionProperties> exts(extCount);
                if(vkEnumerateDeviceExtensionProperties(devices[0],nullptr,&extCount,exts.data())==VK_SUCCESS) {
                    for(uint32_t i=0;i<extCount;i++) {
                        if(std::strcmp(exts[i].extensionName,VK_KHR_SWAPCHAIN_EXTENSION_NAME)==0)
                            hasSwapchain=true;
                    }
                }
            }
            out<<"\"vk_khr_swapchain_device_extension_present\":"
               <<(hasSwapchain?"true":"false")<<",";
            out<<"\"gpu_properties_queried\":true,";
        } else {
            out<<"\"gpu_properties_queried\":false,";
        }
    } else {
        out<<"\"gpu_properties_queried\":false,";
    }
    if (created) vkDestroyInstance(instance,nullptr);
    out<<"\"vk_instance_destroyed_after_test\":"<<(created?"true":"false")<<",";
    out<<"\"original_game_asset_shader_compatibility_proven\":false";
    out<<"}";
    return out.str();
}
} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_rm11cor_carxstreet_portlab_NativeVulkanProbe_probeNativeVulkan(
        JNIEnv* env, jclass) {
    const std::string result=nativeReport();
    return env->NewStringUTF(result.c_str());
}
