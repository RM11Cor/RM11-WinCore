/*
 * Original KERNIX Vulkan hardware enumeration v1.
 * SPDX-License-Identifier: MIT
 * No surface, swapchain, queue, driver overrides, game launch or Wine.
 * Each probe creates/destroys only its own Vulkan instance.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <vulkan/vulkan.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX GPU enumeration supports Android ARM64 only
#endif
#define KERNIX_GPU_EXPORT __attribute__((visibility("default")))
#define KERNIX_NAME_BYTES 256u

struct kernix_gpu_report_v1 {
    uint32_t struct_size;
    uint32_t status;
    uint32_t device_count;
    uint32_t vendor_id;
    uint32_t device_id;
    uint32_t api_version;
    char device_name[KERNIX_NAME_BYTES];
};

/* status=1: enumerated, 2: no Vulkan loader, 3: global functions missing,
 * 4: vkCreateInstance failure, 5: enumeration failure, 6: no GPU.
 */
KERNIX_GPU_EXPORT uint32_t kernix_gpu_probe_v1(struct kernix_gpu_report_v1 *out) {
    if (!out || out->struct_size < sizeof(*out)) return 0u;
    const uint32_t allocated = out->struct_size;
    memset(out, 0, sizeof(*out));
    out->struct_size = allocated;
    void *lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { out->status=2; return out->status; }

    void *p = dlsym(lib, "vkGetInstanceProcAddr");
    PFN_vkGetInstanceProcAddr get = NULL;
    if (p) memcpy(&get, &p, sizeof(get));
    if (!get) { out->status=3; dlclose(lib); return out->status; }

    PFN_vkCreateInstance create =
        (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create) { out->status=3; dlclose(lib); return out->status; }
    const VkApplicationInfo app = {
        .sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName="KERNIX hardware survey",
        .applicationVersion=VK_MAKE_VERSION(1,0,0),
        .pEngineName="KERNIX native host",
        .engineVersion=VK_MAKE_VERSION(1,0,0),
        .apiVersion=VK_API_VERSION_1_0
    };
    const VkInstanceCreateInfo ci = {
        .sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo=&app
    };
    VkInstance instance=VK_NULL_HANDLE;
    VkResult created = create(&ci, NULL, &instance);
    if (created != VK_SUCCESS || instance==VK_NULL_HANDLE) {
        out->status=4;
        dlclose(lib);
        return out->status;
    }
    PFN_vkDestroyInstance destroy =
        (PFN_vkDestroyInstance)get(instance, "vkDestroyInstance");
    PFN_vkEnumeratePhysicalDevices enumerate =
        (PFN_vkEnumeratePhysicalDevices)get(instance, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties properties =
        (PFN_vkGetPhysicalDeviceProperties)get(instance, "vkGetPhysicalDeviceProperties");

    if (!destroy || !enumerate || !properties) {
        out->status=3;
    } else {
        uint32_t count=0;
        VkResult r=enumerate(instance, &count, NULL);
        if (r != VK_SUCCESS) out->status=5;
        else if (count==0) out->status=6;
        else {
            /* Enumerate just one handle safely; VK_INCOMPLETE is allowed. */
            VkPhysicalDevice gpu=VK_NULL_HANDLE;
            uint32_t capacity=1;
            r=enumerate(instance, &capacity, &gpu);
            if ((r==VK_SUCCESS || r==VK_INCOMPLETE) && capacity>0 &&
                gpu!=VK_NULL_HANDLE) {
                VkPhysicalDeviceProperties prop;
                memset(&prop,0,sizeof(prop));
                properties(gpu,&prop);
                out->device_count=count;
                out->vendor_id=prop.vendorID;
                out->device_id=prop.deviceID;
                out->api_version=prop.apiVersion;
                memcpy(out->device_name,prop.deviceName,KERNIX_NAME_BYTES);
                out->device_name[KERNIX_NAME_BYTES-1]='\0';
                out->status=1;
            } else out->status=5;
        }
    }
    /* Destroy even if one of the query functions failed; missing destroy is
     * catastrophic driver-loader mismatch. Do not dlclose a live instance. */
    if (destroy) {
        destroy(instance,NULL);
        dlclose(lib);
    } else {
        /* Do not unload an active instance's code; process teardown owns it. */
    }
    return out->status;
}
