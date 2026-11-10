#include <jni.h>
#include <vulkan/vulkan.h>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>

namespace {
void check(VkResult rc, const char* label) {
    if (rc != VK_SUCCESS) throw std::runtime_error(std::string(label) + ": " + std::to_string(rc));
}
const char* yesno(bool value) { return value ? "YES" : "NO"; }
bool supported(VkPhysicalDevice gpu, VkFormat format) {
    VkFormatProperties props{};
    vkGetPhysicalDeviceFormatProperties(gpu,format,&props);
    if ((props.optimalTilingFeatures & VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT) == 0) return false;
    VkImageFormatProperties imageProps{};
    VkResult rc = vkGetPhysicalDeviceImageFormatProperties(gpu,format,VK_IMAGE_TYPE_2D,
        VK_IMAGE_TILING_OPTIMAL,VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT,0,&imageProps);
    return rc == VK_SUCCESS;
}
std::string runProbe() {
    VkInstance instance=VK_NULL_HANDLE;
    VkApplicationInfo app{};
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="FH5 Native Port M19 Probe";
    app.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo create{};
    create.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    create.pApplicationInfo=&app;
    check(vkCreateInstance(&create,nullptr,&instance),"vkCreateInstance");
    try {
        uint32_t count=0;
        check(vkEnumeratePhysicalDevices(instance,&count,nullptr),"Enumerate GPU count");
        if (!count) throw std::runtime_error("No Vulkan physical device found");
        std::vector<VkPhysicalDevice> devices(count);
        check(vkEnumeratePhysicalDevices(instance,&count,devices.data()),"Enumerate GPUs");
        auto gpu=devices[0];
        VkPhysicalDeviceProperties props{};
        VkPhysicalDeviceFeatures features{};
        vkGetPhysicalDeviceProperties(gpu,&props);
        vkGetPhysicalDeviceFeatures(gpu,&features);
        std::ostringstream out;
        out<<"FH5 M19 Vulkan diagnostic\n";
        out<<"GPU: "<<props.deviceName<<"\n";
        out<<"Vulkan driver API: "<<VK_VERSION_MAJOR(props.apiVersion)<<"."<<VK_VERSION_MINOR(props.apiVersion)<<"."<<VK_VERSION_PATCH(props.apiVersion)<<"\n";
        out<<"BC compression feature: "<<yesno(features.textureCompressionBC)<<"\n";
        out<<"ASTC LDR feature: "<<yesno(features.textureCompressionASTC_LDR)<<"\n";
        out<<"BC7 (sampled+copy): "<<yesno(features.textureCompressionBC && supported(gpu,VK_FORMAT_BC7_UNORM_BLOCK))<<"\n";
        out<<"R8 (sampled+copy): "<<yesno(supported(gpu,VK_FORMAT_R8_UNORM))<<"\n";
        out<<"RGBA16 (sampled+copy): "<<yesno(supported(gpu,VK_FORMAT_R16G16B16A16_UNORM))<<"\n";
        out<<"RGBA8 fallback: "<<yesno(supported(gpu,VK_FORMAT_R8G8B8A8_UNORM))<<"\n";
        out<<"Result: format capability inspection only. No textures uploaded.\n";
        vkDestroyInstance(instance,nullptr);
        return out.str();
    } catch (...) {
        vkDestroyInstance(instance,nullptr);
        throw;
    }
}
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_r4_fh5probe_MainActivity_nativeProbe(JNIEnv* env, jclass) {
    try {
        std::string result=runProbe();
        return env->NewStringUTF(result.c_str());
    } catch (const std::exception& err) {
        std::string error=std::string("Vulkan failed: ") + err.what();
        return env->NewStringUTF(error.c_str());
    }
}
