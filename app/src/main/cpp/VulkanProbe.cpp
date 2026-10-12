#include <jni.h>
#include <vulkan/vulkan.h>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {
std::string vkVersion(uint32_t v) {
    std::ostringstream out;
    out << VK_VERSION_MAJOR(v) << '.' << VK_VERSION_MINOR(v) << '.' << VK_VERSION_PATCH(v);
    return out.str();
}
std::string status(VkResult result) {
    return std::to_string(static_cast<int>(result));
}
std::string runInspection() {
    std::ostringstream out;
    uint32_t supportedApi = VK_API_VERSION_1_0;
    // Supported on Android 11+ Vulkan loader. If unavailable, report Vulkan 1.0 as baseline.
    auto enumerateVersion = reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
        vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkEnumerateInstanceVersion"));
    if (enumerateVersion) enumerateVersion(&supportedApi);
    out << "Vulkan loader API: " << vkVersion(supportedApi) << '\n';

    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "RM11 WinCore Probe";
    appInfo.apiVersion = std::min(supportedApi, VK_API_VERSION_1_1);

    VkInstanceCreateInfo instanceInfo{};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = vkCreateInstance(&instanceInfo, nullptr, &instance);
    if (result != VK_SUCCESS) {
        out << "vkCreateInstance error: " << status(result);
        return out.str();
    }
    uint32_t count = 0;
    result = vkEnumeratePhysicalDevices(instance, &count, nullptr);
    if (result != VK_SUCCESS || count == 0) {
        out << "No Vulkan physical device (result " << status(result) << ")";
        vkDestroyInstance(instance, nullptr);
        return out.str();
    }
    std::vector<VkPhysicalDevice> devices(count);
    result = vkEnumeratePhysicalDevices(instance, &count, devices.data());
    if (result != VK_SUCCESS && result != VK_INCOMPLETE) {
        out << "vkEnumeratePhysicalDevices error: " << status(result);
        vkDestroyInstance(instance, nullptr);
        return out.str();
    }
    for (uint32_t d = 0; d < count; ++d) {
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(devices[d], &props);
        out << "\n=== GPU " << (d + 1) << " ===\n";
        out << "Name: " << props.deviceName << '\n';
        out << "API version: " << vkVersion(props.apiVersion) << '\n';
        out << "Driver version (vendor encoded): " << props.driverVersion << '\n';
        out << "Vendor ID: 0x" << std::hex << props.vendorID << std::dec << '\n';
        out << "Device ID: 0x" << std::hex << props.deviceID << std::dec << '\n';
        out << "Max 2D image size: " << props.limits.maxImageDimension2D << '\n';
        VkPhysicalDeviceMemoryProperties mem{};
        vkGetPhysicalDeviceMemoryProperties(devices[d], &mem);
        // Unified-memory mobile GPUs do not have a separately usable "VRAM" figure.
        out << "Memory heaps (shared/unified possible): " << mem.memoryHeapCount << '\n';
        for (uint32_t i = 0; i < mem.memoryHeapCount; ++i) {
            uint64_t bytes = mem.memoryHeaps[i].size;
            out << " Heap " << i << ": " << (bytes / (1024ULL * 1024ULL)) << " MiB";
            out << ((mem.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) ? " [device-local]" : "") << '\n';
        }
        uint32_t numExtensions = 0;
        result = vkEnumerateDeviceExtensionProperties(devices[d], nullptr, &numExtensions, nullptr);
        if (result != VK_SUCCESS) {
            out << "Cannot query Vulkan extensions: " << status(result) << '\n';
            continue;
        }
        std::vector<VkExtensionProperties> extensions(numExtensions);
        if (numExtensions > 0) {
            result = vkEnumerateDeviceExtensionProperties(devices[d], nullptr, &numExtensions, extensions.data());
            if (result != VK_SUCCESS && result != VK_INCOMPLETE) {
                out << "Cannot read Vulkan extensions: " << status(result) << '\n';
                continue;
            }
        }
        const char* important[] = {
            "VK_KHR_swapchain", "VK_KHR_timeline_semaphore", "VK_KHR_synchronization2",
            "VK_KHR_dynamic_rendering", "VK_EXT_descriptor_indexing",
            "VK_KHR_buffer_device_address", "VK_EXT_robustness2", "VK_EXT_memory_budget"
        };
        out << "Extensions (extension presence does not prove feature support):\n";
        for (const char* requested : important) {
            bool exists = false;
            for (const auto& ext : extensions) {
                if (std::string(ext.extensionName) == requested) { exists = true; break; }
            }
            out << " " << requested << ": " << (exists ? "YES" : "NO (check core API where applicable)") << '\n';
        }

        // Query real feature booleans: extension presence alone is insufficient.
        out << "Feature support (queried from GPU):\n";
        auto getFeatures2 = reinterpret_cast<PFN_vkGetPhysicalDeviceFeatures2>(
            vkGetInstanceProcAddr(instance, "vkGetPhysicalDeviceFeatures2"));
        if (!getFeatures2) {
            out << " feature query: UNAVAILABLE\n";
        } else {
            VkPhysicalDeviceFeatures2 f2{};
            f2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
            VkPhysicalDeviceVulkan12Features f12{};
            f12.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES;
            VkPhysicalDeviceVulkan13Features f13{};
            f13.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES;
            VkPhysicalDeviceRobustness2FeaturesEXT robustness2{};
            robustness2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ROBUSTNESS_2_FEATURES_EXT;
            const bool has12 = props.apiVersion >= VK_API_VERSION_1_2;
            const bool has13 = props.apiVersion >= VK_API_VERSION_1_3;
            bool hasRobustness2 = false;
            for (const auto& ext : extensions) {
                if (std::string(ext.extensionName) == "VK_EXT_robustness2") {
                    hasRobustness2 = true;
                    break;
                }
            }
            void** next = &f2.pNext;
            if (has12) {
                *next = &f12;
                next = &f12.pNext;
            }
            if (has13) {
                *next = &f13;
                next = &f13.pNext;
            }
            if (hasRobustness2) {
                *next = &robustness2;
            }
            getFeatures2(devices[d], &f2);
            auto boolStr = [](VkBool32 b) { return b ? "YES" : "NO"; };
            out << " shaderInt64: " << boolStr(f2.features.shaderInt64) << '\n';
            if (has12) {
                out << " descriptorIndexing: " << boolStr(f12.descriptorIndexing) << '\n';
                out << " runtimeDescriptorArray: " << boolStr(f12.runtimeDescriptorArray) << '\n';
                out << " timelineSemaphore: " << boolStr(f12.timelineSemaphore) << '\n';
                out << " bufferDeviceAddress: " << boolStr(f12.bufferDeviceAddress) << '\n';
            } else {
                out << " Vulkan 1.2 core features: NOT QUERIED\n";
            }
            if (has13) {
                out << " synchronization2: " << boolStr(f13.synchronization2) << '\n';
                out << " dynamicRendering: " << boolStr(f13.dynamicRendering) << '\n';
            } else {
                out << " Vulkan 1.3 core features: NOT QUERIED\n";
            }
            if (hasRobustness2) {
                out << " robustBufferAccess2: " << boolStr(robustness2.robustBufferAccess2) << '\n';
                out << " nullDescriptor: " << boolStr(robustness2.nullDescriptor) << '\n';
            } else {
                out << " VK_EXT_robustness2 features: NOT AVAILABLE\n";
            }
        }
    }
    vkDestroyInstance(instance, nullptr);
    return out.str();
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_rm11_wincore_VulkanProbe_nativeInspect(JNIEnv* env, jclass) {
    try {
        std::string answer = runInspection();
        return env->NewStringUTF(answer.c_str());
    } catch (...) {
        return env->NewStringUTF("Native Vulkan probe unexpected failure");
    }
}
