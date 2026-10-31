#define VK_USE_PLATFORM_ANDROID_KHR 1
#include <jni.h>
#include <dlfcn.h>
#include <android/native_window_jni.h>
#include <android/native_window.h>
#include <vulkan/vulkan.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Proof of real Vulkan GPU transfer commands + display presentation.
 * Intentionally no pipeline/shaders: later phase will measure shader workloads.
 */
static double seconds_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}
static uint32_t clamp_u32(uint32_t x, uint32_t lo, uint32_t hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
static uint32_t alpha_mode(VkCompositeAlphaFlagsKHR modes) {
    const VkCompositeAlphaFlagBitsKHR choices[] = {
        VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
        VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR,
        VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR,
        VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR
    };
    for (size_t i = 0; i < 4; ++i) if (modes & choices[i]) return choices[i];
    return VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
}

/* This stage remains an opt-in test: QueuePresent success is not Wine or DXVK proof. */
JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_RM11PrivateTurnipSurface_nativeRun(JNIEnv *env, jclass cls,
                                                       jobject surfaceObj, jstring signedPath, jint requested) {
    (void)cls;
    char message[1200] = {0};
    const char *gpu = "PRIVATE_APK_TURNIP";
    const char *stage = "start";
    VkResult rc = VK_SUCCESS;
    uint32_t frames = 0, width = 0, height = 0;
    double fps = 0.0, frame_ms = 0.0;
    bool success = false;
    bool hasSurface=false,hasAndroid=false,hasXlib=false,hasWayland=false;
    bool checkedInstanceExtensions=false;
    ANativeWindow *window = NULL;
    VkInstance instance = VK_NULL_HANDLE;
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkSwapchainKHR swapchain = VK_NULL_HANDLE;
    VkCommandPool commandPool = VK_NULL_HANDLE;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    VkSemaphore acquired = VK_NULL_HANDLE, finished = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    VkQueue graphicsQueue = VK_NULL_HANDLE, presentQueue = VK_NULL_HANDLE;
    VkImage *images = NULL;
    uint32_t graphicsFamily = UINT32_MAX, presentFamily = UINT32_MAX;
    uint32_t imageCount = 0;
    const char *path = NULL;
    void *privateICD = NULL;
    PFN_vkVoidFunction (*privateGpa)(VkInstance,const char *) = NULL;
    PFN_vkVoidFunction ptr = NULL;

    PFN_vkCreateInstance vkCreateInstance = NULL;
    PFN_vkEnumerateInstanceExtensionProperties vkEnumerateInstanceExtensionProperties = NULL;
    PFN_vkCreateAndroidSurfaceKHR vkCreateAndroidSurfaceKHR = NULL;
    PFN_vkDestroySurfaceKHR vkDestroySurfaceKHR = NULL;
    PFN_vkDestroyInstance vkDestroyInstance = NULL;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = NULL;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties vkGetPhysicalDeviceQueueFamilyProperties = NULL;
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR vkGetPhysicalDeviceSurfaceSupportKHR = NULL;
    PFN_vkEnumerateDeviceExtensionProperties vkEnumerateDeviceExtensionProperties = NULL;
    PFN_vkGetPhysicalDeviceProperties vkGetPhysicalDeviceProperties = NULL;
    PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR vkGetPhysicalDeviceSurfaceCapabilitiesKHR = NULL;
    PFN_vkGetPhysicalDeviceSurfaceFormatsKHR vkGetPhysicalDeviceSurfaceFormatsKHR = NULL;
    PFN_vkCreateDevice vkCreateDevice = NULL;
    PFN_vkGetDeviceProcAddr vkGetDeviceProcAddr = NULL;
    PFN_vkGetDeviceQueue vkGetDeviceQueue = NULL;
    PFN_vkCreateSwapchainKHR vkCreateSwapchainKHR = NULL;
    PFN_vkGetSwapchainImagesKHR vkGetSwapchainImagesKHR = NULL;
    PFN_vkCreateCommandPool vkCreateCommandPool = NULL;
    PFN_vkAllocateCommandBuffers vkAllocateCommandBuffers = NULL;
    PFN_vkCreateSemaphore vkCreateSemaphore = NULL;
    PFN_vkCreateFence vkCreateFence = NULL;
    PFN_vkWaitForFences vkWaitForFences = NULL;
    PFN_vkAcquireNextImageKHR vkAcquireNextImageKHR = NULL;
    PFN_vkResetCommandBuffer vkResetCommandBuffer = NULL;
    PFN_vkBeginCommandBuffer vkBeginCommandBuffer = NULL;
    PFN_vkCmdPipelineBarrier vkCmdPipelineBarrier = NULL;
    PFN_vkCmdClearColorImage vkCmdClearColorImage = NULL;
    PFN_vkEndCommandBuffer vkEndCommandBuffer = NULL;
    PFN_vkResetFences vkResetFences = NULL;
    PFN_vkQueueSubmit vkQueueSubmit = NULL;
    PFN_vkQueuePresentKHR vkQueuePresentKHR = NULL;
    PFN_vkQueueWaitIdle vkQueueWaitIdle = NULL;
    PFN_vkDeviceWaitIdle vkDeviceWaitIdle = NULL;
    PFN_vkDestroyFence vkDestroyFence = NULL;
    PFN_vkDestroySemaphore vkDestroySemaphore = NULL;
    PFN_vkDestroyCommandPool vkDestroyCommandPool = NULL;
    PFN_vkDestroySwapchainKHR vkDestroySwapchainKHR = NULL;
    PFN_vkDestroyDevice vkDestroyDevice = NULL;
#define TRY(x, where) do { stage = (where); rc = (x); if (rc != VK_SUCCESS) goto cleanup; } while (0)

    /* Signed manifest is checked in Java before this JNI call. The strict
     * path shape protects against arbitrary library injection; no driver
     * selection affects the rest of Android or the normal Wine process. */
    stage = "PRIVATE_ICD_SIGNED_PATH";
    if (!signedPath) { rc=VK_ERROR_INITIALIZATION_FAILED; goto cleanup; }
    path = (*env)->GetStringUTFChars(env,signedPath,NULL);
    if (!path) { rc=VK_ERROR_OUT_OF_HOST_MEMORY; goto cleanup; }
    size_t plen = strnlen(path,4096);
    const char suffix[]="/libvulkan_freedreno.so";
    if(plen>=4096 || plen<=sizeof(suffix)-1 ||
       strcmp(path+plen-(sizeof(suffix)-1),suffix)!=0 ||
       strncmp(path,"/data/app/",10)!=0 ||
       strstr(path,"/../") || strstr(path,"//")){
        rc=VK_ERROR_INITIALIZATION_FAILED;
        goto cleanup;
    }
    stage = "PRIVATE_ICD_DLOPEN";
    privateICD=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if (!privateICD) { rc=VK_ERROR_INITIALIZATION_FAILED; goto cleanup; }
    ptr = (PFN_vkVoidFunction)dlsym(privateICD,"vk_icdGetInstanceProcAddr");
    if (!ptr || sizeof(privateGpa)!=sizeof(ptr)){
        stage="PRIVATE_ICD_GPA_MISSING"; rc=VK_ERROR_INITIALIZATION_FAILED;goto cleanup;
    }
    memcpy(&privateGpa,&ptr,sizeof(privateGpa));
#define LOAD_I(name) do { \
    ptr=privateGpa(instance,#name); \
    memcpy(&(name),&ptr,sizeof(name)); \
    if (!(name)) {stage="PRIVATE_ICD_MISSING_" #name;rc=VK_ERROR_EXTENSION_NOT_PRESENT;goto cleanup;} \
} while(0)
    LOAD_I(vkCreateInstance);
    LOAD_I(vkEnumerateInstanceExtensionProperties);
    /* Fail closed if this private ICD cannot support Android surfaces.
     * Do not silently replace it with Android's system Vulkan loader. */
    stage="PRIVATE_ICD_INSTANCE_EXTENSION_ENUM";
    uint32_t extensionCount=0;
    TRY(vkEnumerateInstanceExtensionProperties(NULL,&extensionCount,NULL),
        "PRIVATE_ICD_INSTANCE_EXTENSION_COUNT");
    if (extensionCount==0 || extensionCount>256) {
        stage="PRIVATE_ICD_INSTANCE_EXTENSION_COUNT_INVALID";
        rc=VK_ERROR_EXTENSION_NOT_PRESENT;goto cleanup;
    }
    VkExtensionProperties exts[256];
    TRY(vkEnumerateInstanceExtensionProperties(NULL,&extensionCount,exts),
        "PRIVATE_ICD_INSTANCE_EXTENSION_LIST");
    for(uint32_t i=0;i<extensionCount;i++){
        if(strcmp(exts[i].extensionName,VK_KHR_SURFACE_EXTENSION_NAME)==0)hasSurface=true;
        if(strcmp(exts[i].extensionName,VK_KHR_ANDROID_SURFACE_EXTENSION_NAME)==0)hasAndroid=true;
        if(strcmp(exts[i].extensionName,"VK_KHR_xlib_surface")==0)hasXlib=true;
        if(strcmp(exts[i].extensionName,"VK_KHR_wayland_surface")==0)hasWayland=true;
    }
    checkedInstanceExtensions=true;
    /* This calls the driver ICD directly, without Android's Vulkan loader.
     * A missing Android surface extension proves that THIS DIRECT-ICD path
     * cannot create an ANativeWindow surface. It does not prove Turnip
     * cannot render, or that X11/Android loader WSI cannot be implemented. */
    if(!hasSurface || !hasAndroid){
        stage="PRIVATE_ICD_ANDROID_WSI_EXTENSION_UNAVAILABLE";
        rc=VK_ERROR_EXTENSION_NOT_PRESENT;goto cleanup;
    }

    stage = "ANativeWindow_fromSurface";
    window = ANativeWindow_fromSurface(env, surfaceObj);
    if (window == NULL) { rc = VK_ERROR_INITIALIZATION_FAILED; goto cleanup; }

    VkApplicationInfo appInfo = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "RM11 Vulkan Surface Frame Test",
        .apiVersion = VK_API_VERSION_1_0
    };
    const char *instanceExt[] = { VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME };
    VkInstanceCreateInfo ic = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &appInfo,
        .enabledExtensionCount = 2,
        .ppEnabledExtensionNames = instanceExt
    };
    TRY(vkCreateInstance(&ic, NULL, &instance), "vkCreateInstance(surface extensions)");

    LOAD_I(vkCreateAndroidSurfaceKHR);
    LOAD_I(vkDestroySurfaceKHR);
    LOAD_I(vkDestroyInstance);
    LOAD_I(vkEnumeratePhysicalDevices);
    LOAD_I(vkGetPhysicalDeviceQueueFamilyProperties);
    LOAD_I(vkGetPhysicalDeviceSurfaceSupportKHR);
    LOAD_I(vkEnumerateDeviceExtensionProperties);
    LOAD_I(vkGetPhysicalDeviceProperties);
    LOAD_I(vkGetPhysicalDeviceSurfaceCapabilitiesKHR);
    LOAD_I(vkGetPhysicalDeviceSurfaceFormatsKHR);
    LOAD_I(vkCreateDevice);
    LOAD_I(vkGetDeviceProcAddr);
#define LOAD_D(name) do { \
    ptr=vkGetDeviceProcAddr(device,#name); \
    memcpy(&(name),&ptr,sizeof(name)); \
    if(!(name)){stage="PRIVATE_ICD_MISSING_" #name;rc=VK_ERROR_EXTENSION_NOT_PRESENT;goto cleanup;} \
} while(0)

    VkAndroidSurfaceCreateInfoKHR sci = {
        .sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR,
        .window = window
    };
    TRY(vkCreateAndroidSurfaceKHR(instance, &sci, NULL, &surface), "vkCreateAndroidSurfaceKHR");

    uint32_t numDevices = 0;
    TRY(vkEnumeratePhysicalDevices(instance, &numDevices, NULL), "vkEnumeratePhysicalDevices(count)");
    if (!numDevices || numDevices>8) { stage = "PRIVATE_ICD_GPU_COUNT_INVALID"; rc = VK_ERROR_INITIALIZATION_FAILED; goto cleanup; }
    VkPhysicalDevice *candidates = (VkPhysicalDevice *)calloc(numDevices, sizeof(*candidates));
    if (!candidates) { stage = "out of memory: devices"; rc = VK_ERROR_OUT_OF_HOST_MEMORY; goto cleanup; }
    rc = vkEnumeratePhysicalDevices(instance, &numDevices, candidates);
    if (rc != VK_SUCCESS) { stage = "vkEnumeratePhysicalDevices(list)"; free(candidates); goto cleanup; }
    for (uint32_t d = 0; d < numDevices && !physical; ++d) {
        uint32_t n = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(candidates[d], &n, NULL);
        if (!n || n>128) continue;
        VkQueueFamilyProperties *props = (VkQueueFamilyProperties *)calloc(n, sizeof(*props));
        if (!props) continue;
        vkGetPhysicalDeviceQueueFamilyProperties(candidates[d], &n, props);
        uint32_t gf = UINT32_MAX, pf = UINT32_MAX;
        for (uint32_t i = 0; i < n; ++i) {
            VkBool32 present = VK_FALSE;
            if (vkGetPhysicalDeviceSurfaceSupportKHR(candidates[d], i, surface, &present) != VK_SUCCESS) continue;
            if ((props[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) && gf == UINT32_MAX) gf = i;
            if (present && pf == UINT32_MAX) pf = i;
            if (present && (props[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)) gf = pf = i;
        }
        free(props);
        if (gf != UINT32_MAX && pf != UINT32_MAX) {
            uint32_t extNum = 0;
            if (vkEnumerateDeviceExtensionProperties(candidates[d], NULL, &extNum, NULL) != VK_SUCCESS || extNum>256) continue;
            VkExtensionProperties *exts = (VkExtensionProperties *)calloc(extNum + 1, sizeof(*exts));
            if (!exts) continue;
            VkResult er = vkEnumerateDeviceExtensionProperties(candidates[d], NULL, &extNum, exts);
            bool hasSwapchain = false;
            if (er == VK_SUCCESS) for (uint32_t e = 0; e < extNum; ++e) {
                if (strcmp(exts[e].extensionName, VK_KHR_SWAPCHAIN_EXTENSION_NAME) == 0) hasSwapchain = true;
            }
            free(exts);
            if (hasSwapchain) { physical = candidates[d]; graphicsFamily = gf; presentFamily = pf; }
        }
    }
    free(candidates);
    if (!physical) { stage = "No GPU with graphics/present/swapchain"; rc = VK_ERROR_FEATURE_NOT_PRESENT; goto cleanup; }
    /* Device identity is obtained from private Turnip, but no arbitrary
       driver text is interpolated into the JSON report. */

    float priority = 1.0f;
    VkDeviceQueueCreateInfo queues[2] = {
        { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
          .queueFamilyIndex = graphicsFamily, .queueCount = 1, .pQueuePriorities = &priority },
        { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
          .queueFamilyIndex = presentFamily, .queueCount = 1, .pQueuePriorities = &priority }
    };
    const char *devExt = VK_KHR_SWAPCHAIN_EXTENSION_NAME;
    VkDeviceCreateInfo dc = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = graphicsFamily == presentFamily ? 1u : 2u,
        .pQueueCreateInfos = queues, .enabledExtensionCount = 1,
        .ppEnabledExtensionNames = &devExt
    };
    TRY(vkCreateDevice(physical, &dc, NULL, &device), "vkCreateDevice");
    LOAD_D(vkGetDeviceQueue);
    LOAD_D(vkCreateSwapchainKHR);
    LOAD_D(vkGetSwapchainImagesKHR);
    LOAD_D(vkCreateCommandPool);
    LOAD_D(vkAllocateCommandBuffers);
    LOAD_D(vkCreateSemaphore);
    LOAD_D(vkCreateFence);
    LOAD_D(vkWaitForFences);
    LOAD_D(vkAcquireNextImageKHR);
    LOAD_D(vkResetCommandBuffer);
    LOAD_D(vkBeginCommandBuffer);
    LOAD_D(vkCmdPipelineBarrier);
    LOAD_D(vkCmdClearColorImage);
    LOAD_D(vkEndCommandBuffer);
    LOAD_D(vkResetFences);
    LOAD_D(vkQueueSubmit);
    LOAD_D(vkQueuePresentKHR);
    LOAD_D(vkQueueWaitIdle);
    LOAD_D(vkDeviceWaitIdle);
    LOAD_D(vkDestroyFence);
    LOAD_D(vkDestroySemaphore);
    LOAD_D(vkDestroyCommandPool);
    LOAD_D(vkDestroySwapchainKHR);
    LOAD_D(vkDestroyDevice);
    vkGetDeviceQueue(device, graphicsFamily, 0, &graphicsQueue);
    vkGetDeviceQueue(device, presentFamily, 0, &presentQueue);

    VkSurfaceCapabilitiesKHR caps;
    TRY(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical, surface, &caps), "SurfaceCapabilities");
    if (!(caps.supportedUsageFlags & VK_IMAGE_USAGE_TRANSFER_DST_BIT)) {
        stage = "Swapchain images lack TRANSFER_DST usage"; rc = VK_ERROR_FORMAT_NOT_SUPPORTED; goto cleanup;
    }
    uint32_t nFormats = 0;
    TRY(vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &nFormats, NULL), "SurfaceFormats(count)");
    if (!nFormats || nFormats>256) { stage = "SurfaceFormats(empty_or_oversized)"; rc = VK_ERROR_FORMAT_NOT_SUPPORTED; goto cleanup; }
    VkSurfaceFormatKHR *formats = (VkSurfaceFormatKHR *)calloc(nFormats, sizeof(*formats));
    if (!formats) { stage = "out of memory: formats"; rc = VK_ERROR_OUT_OF_HOST_MEMORY; goto cleanup; }
    rc = vkGetPhysicalDeviceSurfaceFormatsKHR(physical, surface, &nFormats, formats);
    if (rc != VK_SUCCESS) { stage = "SurfaceFormats(list)"; free(formats); goto cleanup; }
    VkSurfaceFormatKHR format = formats[0];
    for (uint32_t i = 0; i < nFormats; ++i) {
        if (formats[i].format == VK_FORMAT_R8G8B8A8_UNORM || formats[i].format == VK_FORMAT_B8G8R8A8_UNORM) {
            format = formats[i]; break;
        }
    }
    free(formats);
    if (format.format == VK_FORMAT_UNDEFINED) {
        format.format = VK_FORMAT_R8G8B8A8_UNORM;
    }

    VkExtent2D extent = caps.currentExtent;
    if (extent.width == UINT32_MAX) {
        extent.width = clamp_u32((uint32_t)ANativeWindow_getWidth(window),
                                 caps.minImageExtent.width, caps.maxImageExtent.width);
        extent.height = clamp_u32((uint32_t)ANativeWindow_getHeight(window),
                                  caps.minImageExtent.height, caps.maxImageExtent.height);
    }
    if (!extent.width || !extent.height) { stage = "surface dimensions zero"; rc = VK_ERROR_INITIALIZATION_FAILED; goto cleanup; }
    width = extent.width; height = extent.height;
    imageCount = caps.minImageCount + 1;
    if (imageCount>8) {stage="PRIVATE_ICD_SWAPCHAIN_IMAGES_EXCESS";rc=VK_ERROR_INITIALIZATION_FAILED;goto cleanup;}
    if (caps.maxImageCount && imageCount > caps.maxImageCount) imageCount = caps.maxImageCount;
    uint32_t fams[] = { graphicsFamily, presentFamily };
    VkSwapchainCreateInfoKHR sc = {
        .sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR, .surface = surface,
        .minImageCount = imageCount, .imageFormat = format.format,
        .imageColorSpace = format.colorSpace, .imageExtent = extent,
        .imageArrayLayers = 1, .imageUsage = VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .imageSharingMode = graphicsFamily == presentFamily ? VK_SHARING_MODE_EXCLUSIVE : VK_SHARING_MODE_CONCURRENT,
        .queueFamilyIndexCount = graphicsFamily == presentFamily ? 0u : 2u,
        .pQueueFamilyIndices = graphicsFamily == presentFamily ? NULL : fams,
        .preTransform = caps.currentTransform, .compositeAlpha = alpha_mode(caps.supportedCompositeAlpha),
        .presentMode = VK_PRESENT_MODE_FIFO_KHR, .clipped = VK_TRUE
    };
    TRY(vkCreateSwapchainKHR(device, &sc, NULL, &swapchain), "vkCreateSwapchainKHR");
    TRY(vkGetSwapchainImagesKHR(device, swapchain, &imageCount, NULL), "vkGetSwapchainImagesKHR(count)");
    images = (VkImage *)calloc(imageCount, sizeof(*images));
    if (!images) { stage = "out of memory: images"; rc = VK_ERROR_OUT_OF_HOST_MEMORY; goto cleanup; }
    TRY(vkGetSwapchainImagesKHR(device, swapchain, &imageCount, images), "vkGetSwapchainImagesKHR(list)");

    VkCommandPoolCreateInfo pc = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        .queueFamilyIndex = graphicsFamily
    };
    TRY(vkCreateCommandPool(device, &pc, NULL, &commandPool), "vkCreateCommandPool");
    VkCommandBufferAllocateInfo ca = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = commandPool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount = 1
    };
    TRY(vkAllocateCommandBuffers(device, &ca, &cmd), "vkAllocateCommandBuffers");
    VkSemaphoreCreateInfo si = { .sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO };
    TRY(vkCreateSemaphore(device, &si, NULL, &acquired), "vkCreateSemaphore(acquire)");
    TRY(vkCreateSemaphore(device, &si, NULL, &finished), "vkCreateSemaphore(present)");
    VkFenceCreateInfo fi = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
                             .flags = VK_FENCE_CREATE_SIGNALED_BIT };
    TRY(vkCreateFence(device, &fi, NULL, &fence), "vkCreateFence");

    int maxFrames = requested < 12 ? 12 : requested > 60 ? 60 : requested;
    double started = seconds_now();
    for (int i = 0; i < maxFrames; ++i) {
        stage = "vkWaitForFences";
        TRY(vkWaitForFences(device, 1, &fence, VK_TRUE, 5000000000ULL), "vkWaitForFences");
        uint32_t idx = 0;
        rc = vkAcquireNextImageKHR(device, swapchain, 5000000000ULL, acquired, VK_NULL_HANDLE, &idx);
        if (rc != VK_SUCCESS && rc != VK_SUBOPTIMAL_KHR) { stage = "vkAcquireNextImageKHR (surface resize?)"; goto cleanup; }
        TRY(vkResetCommandBuffer(cmd, 0), "vkResetCommandBuffer");
        VkCommandBufferBeginInfo begin = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
        TRY(vkBeginCommandBuffer(cmd, &begin), "vkBeginCommandBuffer");
        VkImageMemoryBarrier intoTransfer = {
            .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
            .srcAccessMask = 0, .dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
            .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED, .newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
            .image = images[idx],
            .subresourceRange = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1 }
        };
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                             0, 0, NULL, 0, NULL, 1, &intoTransfer);
        float f = (float)(i % 120) / 119.0f;
        VkClearColorValue color = { .float32 = { 0.10f + 0.77f * f, 0.18f, 0.85f - 0.7f * f, 1.0f } };
        VkImageSubresourceRange range = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1 };
        vkCmdClearColorImage(cmd, images[idx], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &color, 1, &range);
        VkImageMemoryBarrier intoPresent = intoTransfer;
        intoPresent.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        intoPresent.dstAccessMask = 0;
        intoPresent.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        intoPresent.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
                             0, 0, NULL, 0, NULL, 1, &intoPresent);
        TRY(vkEndCommandBuffer(cmd), "vkEndCommandBuffer");
        TRY(vkResetFences(device, 1, &fence), "vkResetFences");
        VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_TRANSFER_BIT;
        VkSubmitInfo sub = {
            .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
            .waitSemaphoreCount = 1, .pWaitSemaphores = &acquired,
            .pWaitDstStageMask = &waitStage,
            .commandBufferCount = 1, .pCommandBuffers = &cmd,
            .signalSemaphoreCount = 1, .pSignalSemaphores = &finished
        };
        TRY(vkQueueSubmit(graphicsQueue, 1, &sub, fence), "vkQueueSubmit");
        VkPresentInfoKHR present = {
            .sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
            .waitSemaphoreCount = 1, .pWaitSemaphores = &finished,
            .swapchainCount = 1, .pSwapchains = &swapchain, .pImageIndices = &idx
        };
        rc = vkQueuePresentKHR(presentQueue, &present);
        if (rc != VK_SUCCESS && rc != VK_SUBOPTIMAL_KHR) { stage = "vkQueuePresentKHR (surface resize?)"; goto cleanup; }
        /* Synchronize this diagnostic loop to avoid reusing present semaphore too early. */
        TRY(vkQueueWaitIdle(presentQueue), "vkQueueWaitIdle(present)");
        frames++;
    }
    {
        double duration = seconds_now() - started;
        if (duration > 0) { fps = (double)frames / duration; frame_ms = 1000.0 * duration / (double)frames; }
    }
    stage = "completed swapchain clear/present test";
    success = frames == (uint32_t)maxFrames;
    rc = VK_SUCCESS;

cleanup:
    if (device && vkDeviceWaitIdle) vkDeviceWaitIdle(device);
    if (fence && vkDestroyFence) vkDestroyFence(device, fence, NULL);
    if (acquired && vkDestroySemaphore) vkDestroySemaphore(device, acquired, NULL);
    if (finished && vkDestroySemaphore) vkDestroySemaphore(device, finished, NULL);
    if (commandPool && vkDestroyCommandPool) vkDestroyCommandPool(device, commandPool, NULL);
    if (swapchain && vkDestroySwapchainKHR) vkDestroySwapchainKHR(device, swapchain, NULL);
    free(images);
    if (device && vkDestroyDevice) vkDestroyDevice(device, NULL);
    if (surface && vkDestroySurfaceKHR) vkDestroySurfaceKHR(instance, surface, NULL);
    if (instance && vkDestroyInstance) vkDestroyInstance(instance, NULL);
    if (window) ANativeWindow_release(window);
    if (privateICD) dlclose(privateICD);
    if (path) (*env)->ReleaseStringUTFChars(env,signedPath,path);
    snprintf(message, sizeof(message),
             "{\"schema\":\"rm11.turnip-android-wsi.v1\",\"private_turnip_icd\":true,\"wine_dxvk_proven\":false,\"success\":%s,\"gpu\":\"%s\",\"width\":%u,\"height\":%u,"
             "\"frames\":%u,\"fps\":%.2f,\"frameMs\":%.2f,\"vkResult\":%d,"
             "\"instanceExtensionsChecked\":%s,\"supportsKhrSurface\":%s,"
             "\"supportsAndroidSurface\":%s,\"supportsXlibSurface\":%s,"
             "\"supportsWaylandSurface\":%s,"
             "\"wsiRoute\":\"DIRECT_PRIVATE_ICD_NO_PLATFORM_LOADER\","
             "\"stage\":\"%s\"}",
             success ? "true" : "false", gpu, width, height, frames, fps, frame_ms, (int)rc,
             checkedInstanceExtensions?"true":"false",
             hasSurface?"true":"false",hasAndroid?"true":"false",
             hasXlib?"true":"false",hasWayland?"true":"false",stage);
    return (*env)->NewStringUTF(env, message);
#undef TRY
#undef LOAD_I
#undef LOAD_D
}
