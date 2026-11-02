/* SPDX-License-Identifier: MIT
 * KERNIX independent Android Vulkan presentation bootstrap.
 * Creates a real VkSurfaceKHR from an ANativeWindow and verifies that an
 * AArch64 Android Vulkan GPU has a queue family capable of presenting.
 * It does not create a swapchain, render images or run Windows programs.
 */
#include <android/native_window.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error Android ARM64 only
#endif
#define KERNIX_EXPORT __attribute__((visibility("default")))

enum {
  KERNIX_SURFACE_OK = 0,
  KERNIX_SURFACE_BAD_ARG = 1,
  KERNIX_SURFACE_LOADER_MISSING = 2,
  KERNIX_SURFACE_ENTRY_MISSING = 3,
  KERNIX_SURFACE_INSTANCE_FAILED = 4,
  KERNIX_SURFACE_EXTENSION_MISSING = 5,
  KERNIX_SURFACE_CREATE_FAILED = 6,
  KERNIX_SURFACE_NO_PHYSICAL_DEVICE = 7,
  KERNIX_SURFACE_NO_PRESENT_QUEUE = 8
};

struct kernix_surface_report_v1 {
  uint32_t struct_size;
  uint32_t status;
  uint32_t device_count;
  uint32_t queue_family_index;
  uint32_t gpu_api_version;
  uint32_t window_width;
  uint32_t window_height;
  uint32_t vk_error_code;
};

KERNIX_EXPORT uint32_t kernix_surface_probe_v1(
    ANativeWindow *window, struct kernix_surface_report_v1 *out) {
  if (!out || out->struct_size < sizeof(*out) || !window)
    return KERNIX_SURFACE_BAD_ARG;
  memset((char *)out + sizeof(out->struct_size), 0,
         sizeof(*out) - sizeof(out->struct_size));
  out->window_width = (uint32_t)ANativeWindow_getWidth(window);
  out->window_height = (uint32_t)ANativeWindow_getHeight(window);
  out->queue_family_index = UINT32_MAX;
  out->status = KERNIX_SURFACE_LOADER_MISSING;
  void *loader = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
  if (!loader) return out->status;
  PFN_vkGetInstanceProcAddr get_proc = NULL;
  void *p = dlsym(loader, "vkGetInstanceProcAddr");
  if (p) memcpy(&get_proc, &p, sizeof(get_proc));
  if (!get_proc) {
    out->status = KERNIX_SURFACE_ENTRY_MISSING;
    dlclose(loader);
    return out->status;
  }
  PFN_vkCreateInstance create_instance =
      (PFN_vkCreateInstance)get_proc(VK_NULL_HANDLE, "vkCreateInstance");
  PFN_vkEnumerateInstanceExtensionProperties ext_props =
      (PFN_vkEnumerateInstanceExtensionProperties)get_proc(
          VK_NULL_HANDLE, "vkEnumerateInstanceExtensionProperties");
  if (!create_instance || !ext_props) {
    out->status = KERNIX_SURFACE_ENTRY_MISSING;
    dlclose(loader);
    return out->status;
  }
  uint32_t ext_count = 0;
  VkResult err = ext_props(NULL, &ext_count, NULL);
  if (err != VK_SUCCESS || !ext_count || ext_count > 256) {
    out->status = KERNIX_SURFACE_EXTENSION_MISSING;
    out->vk_error_code = (uint32_t)err;
    dlclose(loader);
    return out->status;
  }
  VkExtensionProperties extensions[256];
  err = ext_props(NULL, &ext_count, extensions);
  int has_surface = 0, has_android = 0;
  if (err == VK_SUCCESS) for (uint32_t i=0;i<ext_count;i++) {
    has_surface |= strcmp(extensions[i].extensionName, VK_KHR_SURFACE_EXTENSION_NAME)==0;
    has_android |= strcmp(extensions[i].extensionName, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME)==0;
  }
  if (!has_surface || !has_android) {
    out->status = KERNIX_SURFACE_EXTENSION_MISSING;
    dlclose(loader);
    return out->status;
  }
  const char *enabled[] = { VK_KHR_SURFACE_EXTENSION_NAME,
                            VK_KHR_ANDROID_SURFACE_EXTENSION_NAME };
  VkApplicationInfo app = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
      .pApplicationName = "KERNIX", .apiVersion = VK_API_VERSION_1_0 };
  VkInstanceCreateInfo ci = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
      .pApplicationInfo = &app, .enabledExtensionCount=2,
      .ppEnabledExtensionNames=enabled };
  VkInstance instance = VK_NULL_HANDLE;
  err = create_instance(&ci, NULL, &instance);
  if (err != VK_SUCCESS || !instance) {
    out->status = KERNIX_SURFACE_INSTANCE_FAILED;
    out->vk_error_code = (uint32_t)err;
    dlclose(loader);
    return out->status;
  }
  PFN_vkDestroyInstance destroy_instance =
      (PFN_vkDestroyInstance)get_proc(instance, "vkDestroyInstance");
  PFN_vkCreateAndroidSurfaceKHR create_surface =
      (PFN_vkCreateAndroidSurfaceKHR)get_proc(instance, "vkCreateAndroidSurfaceKHR");
  PFN_vkDestroySurfaceKHR destroy_surface =
      (PFN_vkDestroySurfaceKHR)get_proc(instance, "vkDestroySurfaceKHR");
  PFN_vkEnumeratePhysicalDevices enumerate =
      (PFN_vkEnumeratePhysicalDevices)get_proc(instance, "vkEnumeratePhysicalDevices");
  PFN_vkGetPhysicalDeviceQueueFamilyProperties queue_props =
      (PFN_vkGetPhysicalDeviceQueueFamilyProperties)get_proc(instance,
                                    "vkGetPhysicalDeviceQueueFamilyProperties");
  PFN_vkGetPhysicalDeviceSurfaceSupportKHR surface_support =
      (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)get_proc(instance,
                                    "vkGetPhysicalDeviceSurfaceSupportKHR");
  PFN_vkGetPhysicalDeviceProperties device_props =
      (PFN_vkGetPhysicalDeviceProperties)get_proc(instance, "vkGetPhysicalDeviceProperties");
  VkSurfaceKHR surface = VK_NULL_HANDLE;
  out->status = KERNIX_SURFACE_ENTRY_MISSING;
  if (!create_surface || !destroy_surface || !enumerate || !queue_props
      || !surface_support || !device_props) goto cleanup;
  VkAndroidSurfaceCreateInfoKHR sci = {
      .sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR,
      .window = window };
  err = create_surface(instance, &sci, NULL, &surface);
  if (err != VK_SUCCESS || !surface) {
    out->status = KERNIX_SURFACE_CREATE_FAILED;
    out->vk_error_code = (uint32_t)err;
    goto cleanup;
  }
  uint32_t count = 0;
  err = enumerate(instance, &count, NULL);
  if (err != VK_SUCCESS || count==0 || count>64) {
    out->status = KERNIX_SURFACE_NO_PHYSICAL_DEVICE;
    out->vk_error_code = (uint32_t)err;
    goto cleanup;
  }
  VkPhysicalDevice devices[64];
  err = enumerate(instance, &count, devices);
  if (err != VK_SUCCESS) {
    out->status = KERNIX_SURFACE_NO_PHYSICAL_DEVICE;
    out->vk_error_code = (uint32_t)err;
    goto cleanup;
  }
  out->device_count = count;
  out->status = KERNIX_SURFACE_NO_PRESENT_QUEUE;
  for (uint32_t i=0;i<count;i++) {
    uint32_t families = 0;
    queue_props(devices[i], &families, NULL);
    if (!families || families>256) continue;
    VkQueueFamilyProperties properties[256];
    queue_props(devices[i], &families, properties);
    for (uint32_t q=0;q<families;q++) {
      VkBool32 supported = VK_FALSE;
      err = surface_support(devices[i],q,surface,&supported);
      if (err==VK_SUCCESS && supported && properties[q].queueCount>0 &&
          (properties[q].queueFlags & VK_QUEUE_GRAPHICS_BIT)) {
        VkPhysicalDeviceProperties gpu;
        device_props(devices[i],&gpu);
        out->gpu_api_version = gpu.apiVersion;
        out->queue_family_index = q;
        out->status = KERNIX_SURFACE_OK;
        goto cleanup;
      }
    }
  }
cleanup:
  if (surface && destroy_surface) destroy_surface(instance,surface,NULL);
  if (destroy_instance) destroy_instance(instance,NULL);
  dlclose(loader);
  return out->status;
}
