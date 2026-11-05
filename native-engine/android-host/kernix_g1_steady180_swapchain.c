/* SPDX-License-Identifier: MIT
 * Original KERNIX Android Vulkan swapchain bring-up.
 * A temporary native-window-bound device and swapchain are constructed and
 * fully destroyed after a bounded series of image presentations.
 * Compilation does not prove device presentation or game support.
 * This probe deliberately does not retain window/device across lifecycle.
 */
#include <android/native_window.h>
#include <vulkan/vulkan.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdatomic.h>
static _Atomic int kernix_g1_steady_stop = 0;
void kernix_g1_steady_cancel(void) {
    atomic_store_explicit(&kernix_g1_steady_stop, 1, memory_order_release);
}
void kernix_g1_steady_reset(void) {
    atomic_store_explicit(&kernix_g1_steady_stop, 0, memory_order_release);
}
#ifdef KERNIX_G1_VISUAL_TEST
#include <unistd.h>
#endif

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error Android ARM64 only
#endif

#define KERNIX_EXPORT __attribute__((visibility("default")))
#define KERNIX_SWAPCHAIN_OK 0u
#define KERNIX_SWAPCHAIN_INVALID 1u
#define KERNIX_SWAPCHAIN_INSTANCE_FAILED 2u
#define KERNIX_SWAPCHAIN_SURFACE_FAILED 3u
#define KERNIX_SWAPCHAIN_NO_ADAPTER 4u
#define KERNIX_SWAPCHAIN_NO_QUEUE 5u
#define KERNIX_SWAPCHAIN_UNSUPPORTED 6u
#define KERNIX_SWAPCHAIN_DEVICE_FAILED 7u
#define KERNIX_SWAPCHAIN_CREATE_FAILED 8u
#define KERNIX_SWAPCHAIN_PRESENT_FAILED 9u
#define KERNIX_SWAPCHAIN_CANCELLED 10u

struct kernix_swapchain_report_v1 {
    uint32_t struct_size, status, width, height, images, format;
    uint32_t present_mode, queue_family, vk_error_code, frame_presented;
    uint32_t frames_attempted, frames_completed;
};

static uint32_t report_error(struct kernix_swapchain_report_v1 *r,
                             uint32_t code, VkResult err) {
    r->status = code;
    r->vk_error_code = (uint32_t)err;
    return code;
}


/* Submit a single original solid-color frame and present it with explicit
 * acquire/render/present synchronization. All resources are temporary.
 * A successful CI compile does NOT imply that a real phone presented it. */
static VkResult kernix_present_one_frame(VkDevice device,
                                         VkSwapchainKHR swapchain,
                                         uint32_t family, uint32_t frame_index) {
    VkResult result = VK_ERROR_INITIALIZATION_FAILED;
    VkQueue queue = VK_NULL_HANDLE;
    VkCommandPool pool = VK_NULL_HANDLE;
    VkSemaphore acquired = VK_NULL_HANDLE, rendered = VK_NULL_HANDLE;
    VkCommandBuffer command = VK_NULL_HANDLE;
    uint32_t count = 0, index = 0;
    VkImage images[16];
    vkGetDeviceQueue(device, family, 0, &queue);
    if (!queue) return result;
    result = vkGetSwapchainImagesKHR(device, swapchain, &count, NULL);
    if (result != VK_SUCCESS || count == 0 || count > 16)
        return VK_ERROR_INITIALIZATION_FAILED;
    result = vkGetSwapchainImagesKHR(device, swapchain, &count, images);
    if (result != VK_SUCCESS) return result;
    VkCommandPoolCreateInfo pool_info = {
       .sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
       .queueFamilyIndex=family
    };
    result = vkCreateCommandPool(device, &pool_info, NULL, &pool);
    if (result != VK_SUCCESS) goto cleanup;
    VkSemaphoreCreateInfo sem_info = {
       .sType=VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO
    };
    result=vkCreateSemaphore(device,&sem_info,NULL,&acquired);
    if (result != VK_SUCCESS) goto cleanup;
    result=vkCreateSemaphore(device,&sem_info,NULL,&rendered);
    if (result != VK_SUCCESS) goto cleanup;
    VkCommandBufferAllocateInfo allocate = {
       .sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
       .commandPool=pool,
       .level=VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount=1
    };
    result=vkAllocateCommandBuffers(device,&allocate,&command);
    if (result != VK_SUCCESS) goto cleanup;
    /* Short timeout: never block the Android UI indefinitely on GPU loss. */
    result=vkAcquireNextImageKHR(device,swapchain,250000000ULL,
                                 acquired,VK_NULL_HANDLE,&index);
    if (result != VK_SUCCESS && result != VK_SUBOPTIMAL_KHR) goto cleanup;
    if (index >= count) {result=VK_ERROR_INITIALIZATION_FAILED;goto cleanup;}
    VkCommandBufferBeginInfo begin = {
        .sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    };
    result=vkBeginCommandBuffer(command,&begin);
    if (result != VK_SUCCESS) goto cleanup;
    VkImageMemoryBarrier before = {
        .sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask=0,
        .dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,
        .oldLayout=VK_IMAGE_LAYOUT_UNDEFINED,
        .newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        .srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED,
        .image=images[index],
        .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}
    };
    vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                         VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,1,&before);
    #ifdef KERNIX_G1_VISUAL_TEST
    /* Strong contrasting red/green/blue/yellow per eight queued frames.
       Visibility requires human-observed live phone video, not a CI claim. */
    uint32_t phase=(frame_index/30u)%4u;
    VkClearColorValue color={ .float32={
       (phase==0u||phase==3u)?0.90f:0.04f,
       (phase==1u||phase==3u)?0.88f:0.04f,
       phase==2u?0.95f:0.04f,1.0f} };
#else
    VkClearColorValue color={ .float32={0.035f + 0.04f * (float)(frame_index % 4u),0.13f,0.29f,1.0f} };
#endif
    VkImageSubresourceRange color_range={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
    vkCmdClearColorImage(command,images[index],
                         VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&color,1,&color_range);
    VkImageMemoryBarrier after=before;
    after.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    after.dstAccessMask=0;
    after.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    after.newLayout=VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_TRANSFER_BIT,
                         VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,0,0,NULL,0,NULL,1,&after);
    result=vkEndCommandBuffer(command);
    if (result != VK_SUCCESS) goto cleanup;
    VkPipelineStageFlags wait_stage=VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo submit={
      .sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
      .waitSemaphoreCount=1,.pWaitSemaphores=&acquired,
      .pWaitDstStageMask=&wait_stage,.commandBufferCount=1,
      .pCommandBuffers=&command,.signalSemaphoreCount=1,
      .pSignalSemaphores=&rendered
    };
    result=vkQueueSubmit(queue,1,&submit,VK_NULL_HANDLE);
    if (result != VK_SUCCESS) goto cleanup;
    VkPresentInfoKHR present={
      .sType=VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
      .waitSemaphoreCount=1,.pWaitSemaphores=&rendered,
      .swapchainCount=1,.pSwapchains=&swapchain,.pImageIndices=&index
    };
    result=vkQueuePresentKHR(queue,&present);
cleanup:
    /* Do not destroy semaphores or command memory while the GPU uses them. */
    (void)vkDeviceWaitIdle(device);
    if (rendered) vkDestroySemaphore(device,rendered,NULL);
    if (acquired) vkDestroySemaphore(device,acquired,NULL);
    if (pool) vkDestroyCommandPool(device,pool,NULL);
    return result;
}

static uint32_t kernix_swapchain_probe_once_v1(
        ANativeWindow *window, struct kernix_swapchain_report_v1 *r) {
    if (!window || !r || r->struct_size < sizeof(*r))
        return KERNIX_SWAPCHAIN_INVALID;
    memset((char *)r + sizeof(r->struct_size), 0,
           sizeof(*r) - sizeof(r->struct_size));
    r->status = KERNIX_SWAPCHAIN_INVALID;
    r->queue_family = UINT32_MAX;
    r->width = (uint32_t)ANativeWindow_getWidth(window);
    r->height = (uint32_t)ANativeWindow_getHeight(window);
    if (!r->width || !r->height) return r->status;

    VkInstance instance = VK_NULL_HANDLE;
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkSwapchainKHR swapchain = VK_NULL_HANDLE;
    uint32_t status = KERNIX_SWAPCHAIN_INSTANCE_FAILED;
    VkResult err = VK_SUCCESS;
    const char *instance_exts[] = {
        VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME
    };
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "KERNIX", .apiVersion = VK_API_VERSION_1_0
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app, .enabledExtensionCount = 2,
        .ppEnabledExtensionNames = instance_exts
    };
    err = vkCreateInstance(&ici, NULL, &instance);
    if (err != VK_SUCCESS) goto finish;
    status = KERNIX_SWAPCHAIN_SURFACE_FAILED;
    VkAndroidSurfaceCreateInfoKHR sci = {
        .sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR,
        .window = window
    };
    err = vkCreateAndroidSurfaceKHR(instance, &sci, NULL, &surface);
    if (err != VK_SUCCESS) goto finish;

    uint32_t device_count = 0;
    status = KERNIX_SWAPCHAIN_NO_ADAPTER;
    err = vkEnumeratePhysicalDevices(instance, &device_count, NULL);
    if (err != VK_SUCCESS || !device_count || device_count > 32) goto finish;
    VkPhysicalDevice physical[32];
    err = vkEnumeratePhysicalDevices(instance, &device_count, physical);
    if (err != VK_SUCCESS) goto finish;

    VkPhysicalDevice gpu = VK_NULL_HANDLE;
    status = KERNIX_SWAPCHAIN_NO_QUEUE;
    uint32_t q_index = UINT32_MAX;
    for (uint32_t i = 0; i < device_count && !gpu; ++i) {
        uint32_t family_count = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(physical[i], &family_count, NULL);
        if (!family_count || family_count > 256) continue;
        VkQueueFamilyProperties families[256];
        vkGetPhysicalDeviceQueueFamilyProperties(physical[i], &family_count, families);
        for (uint32_t j = 0; j < family_count; ++j) {
            VkBool32 present = VK_FALSE;
            if (!families[j].queueCount ||
                !(families[j].queueFlags & VK_QUEUE_GRAPHICS_BIT)) continue;
            err = vkGetPhysicalDeviceSurfaceSupportKHR(physical[i],j,surface,&present);
            if (err == VK_SUCCESS && present) {
                gpu = physical[i]; q_index = j; break;
            }
        }
    }
    if (!gpu) goto finish;
    r->queue_family = q_index;

    status = KERNIX_SWAPCHAIN_UNSUPPORTED;
    uint32_t ext_count = 0;
    err = vkEnumerateDeviceExtensionProperties(gpu, NULL, &ext_count, NULL);
    if (err != VK_SUCCESS || !ext_count || ext_count > 1024) goto finish;
    VkExtensionProperties extensions[1024];
    err = vkEnumerateDeviceExtensionProperties(gpu, NULL, &ext_count, extensions);
    if (err != VK_SUCCESS) goto finish;
    VkBool32 supports_swapchain = VK_FALSE;
    for (uint32_t i = 0; i < ext_count; ++i)
        if (strcmp(extensions[i].extensionName,
                   VK_KHR_SWAPCHAIN_EXTENSION_NAME) == 0)
            supports_swapchain = VK_TRUE;
    if (!supports_swapchain) goto finish;

    VkSurfaceCapabilitiesKHR caps;
    err = vkGetPhysicalDeviceSurfaceCapabilitiesKHR(gpu, surface, &caps);
    if (err != VK_SUCCESS) goto finish;
    uint32_t format_count = 0;
    err = vkGetPhysicalDeviceSurfaceFormatsKHR(gpu,surface,&format_count,NULL);
    if (err != VK_SUCCESS || !format_count || format_count > 256) goto finish;
    VkSurfaceFormatKHR formats[256];
    err = vkGetPhysicalDeviceSurfaceFormatsKHR(gpu,surface,&format_count,formats);
    if (err != VK_SUCCESS) goto finish;
    uint32_t mode_count = 0;
    err = vkGetPhysicalDeviceSurfacePresentModesKHR(gpu,surface,&mode_count,NULL);
    if (err != VK_SUCCESS || !mode_count || mode_count > 64) goto finish;
    VkPresentModeKHR modes[64];
    err = vkGetPhysicalDeviceSurfacePresentModesKHR(gpu,surface,&mode_count,modes);
    if (err != VK_SUCCESS) goto finish;
    VkPresentModeKHR present_mode = VK_PRESENT_MODE_FIFO_KHR;
    VkBool32 has_fifo = VK_FALSE;
    for (uint32_t i = 0; i < mode_count; ++i)
        if (modes[i] == VK_PRESENT_MODE_FIFO_KHR) has_fifo = VK_TRUE;
    if (!has_fifo) goto finish;

    VkSurfaceFormatKHR chosen = formats[0];
    for (uint32_t i=0;i<format_count;i++) {
        if (formats[i].format == VK_FORMAT_R8G8B8A8_UNORM ||
            formats[i].format == VK_FORMAT_B8G8R8A8_UNORM) {
            chosen=formats[i]; break;
        }
    }
    if (chosen.format == VK_FORMAT_UNDEFINED)
        chosen.format = VK_FORMAT_R8G8B8A8_UNORM;
    if (!(caps.supportedUsageFlags & VK_IMAGE_USAGE_TRANSFER_DST_BIT))
        goto finish;
    uint32_t width = caps.currentExtent.width;
    uint32_t height = caps.currentExtent.height;
    if (width == UINT32_MAX) {
        width = r->width; height = r->height;
        if (width < caps.minImageExtent.width) width = caps.minImageExtent.width;
        if (width > caps.maxImageExtent.width) width = caps.maxImageExtent.width;
        if (height < caps.minImageExtent.height) height = caps.minImageExtent.height;
        if (height > caps.maxImageExtent.height) height = caps.maxImageExtent.height;
    }
    if (!width || !height) goto finish;
    uint32_t image_count = caps.minImageCount + (caps.minImageCount < UINT32_MAX);
    if (caps.maxImageCount && image_count > caps.maxImageCount)
        image_count = caps.maxImageCount;
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {
        .sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex=q_index, .queueCount=1,
        .pQueuePriorities=&priority
    };
    const char *dev_ext[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
    VkDeviceCreateInfo dci = {
        .sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount=1, .pQueueCreateInfos=&queue_info,
        .enabledExtensionCount=1, .ppEnabledExtensionNames=dev_ext
    };
    status=KERNIX_SWAPCHAIN_DEVICE_FAILED;
    err = vkCreateDevice(gpu,&dci,NULL,&device);
    if (err != VK_SUCCESS) goto finish;
    VkSurfaceTransformFlagBitsKHR transform =
       (caps.supportedTransforms & VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR)
        ? VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR : caps.currentTransform;
    VkCompositeAlphaFlagBitsKHR alpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    if (!(caps.supportedCompositeAlpha & alpha)) {
        if (caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR;
        else if (caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR;
        else if (caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR)
            alpha=VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR;
        else { status=KERNIX_SWAPCHAIN_UNSUPPORTED; goto finish; }
    }
    VkSwapchainCreateInfoKHR swap_info = {
        .sType=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR,
        .surface=surface, .minImageCount=image_count,
        .imageFormat=chosen.format, .imageColorSpace=chosen.colorSpace,
        .imageExtent={width,height}, .imageArrayLayers=1,
        .imageUsage=VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .imageSharingMode=VK_SHARING_MODE_EXCLUSIVE,
        .preTransform=transform, .compositeAlpha=alpha,
        .presentMode=present_mode, .clipped=VK_TRUE
    };
    status=KERNIX_SWAPCHAIN_CREATE_FAILED;
    err = vkCreateSwapchainKHR(device,&swap_info,NULL,&swapchain);
    if (err != VK_SUCCESS) goto finish;
    r->width=width; r->height=height;
    r->images=image_count; r->format=(uint32_t)chosen.format;
    r->present_mode=(uint32_t)present_mode;
    status=KERNIX_SWAPCHAIN_PRESENT_FAILED;
    /* Strictly bounded four-frame run: avoids a permanent rendering thread,
       overheating and indefinite stalls before actual device qualification. */
    #ifdef KERNIX_G1_VISUAL_TEST
    /* Bounded 48 frames with ~3 seconds of inter-frame pacing, no daemon loop. */
    for (uint32_t frame=0; frame<180u; ++frame) {
#else
    for (uint32_t frame=0; frame<4u; ++frame) {
#endif
        if (atomic_load_explicit(&kernix_g1_steady_stop,memory_order_acquire)) {
            status=KERNIX_SWAPCHAIN_CANCELLED;
            err=VK_SUCCESS;
            goto finish;
        }
        r->frames_attempted++;
        err=kernix_present_one_frame(device,swapchain,q_index,frame);
        if (err != VK_SUCCESS && err != VK_SUBOPTIMAL_KHR) goto finish;
        r->frames_completed++;
#ifdef KERNIX_G1_VISUAL_TEST
        if (frame + 1u < 180u) usleep(33000u);
#endif
    }
    r->frame_presented=(r->frames_completed>0u);
    status=KERNIX_SWAPCHAIN_OK;
finish:
    if (device) vkDeviceWaitIdle(device);
    if (swapchain) vkDestroySwapchainKHR(device,swapchain,NULL);
    if (device) vkDestroyDevice(device,NULL);
    if (surface) vkDestroySurfaceKHR(instance,surface,NULL);
    if (instance) vkDestroyInstance(instance,NULL);
    return report_error(r,status,err);
}


/* On surface resize/out-of-date Vulkan requires a fresh swapchain.
 * The entire bootstrap is recreated at most once, never an unbounded retry.
 * NativeWindow ownership remains with the JNI caller. */
KERNIX_EXPORT uint32_t kernix_swapchain_probe_v1(
        ANativeWindow *window, struct kernix_swapchain_report_v1 *report) {
    uint32_t result=kernix_swapchain_probe_once_v1(window,report);
    if (!window || !report || report->struct_size < sizeof(*report))
        return result;
    if ((result==KERNIX_SWAPCHAIN_CREATE_FAILED ||
         result==KERNIX_SWAPCHAIN_PRESENT_FAILED) &&
        ((int32_t)report->vk_error_code==VK_ERROR_OUT_OF_DATE_KHR ||
         (int32_t)report->vk_error_code==VK_SUBOPTIMAL_KHR)) {
        /* Retry only while the native window has a non-zero extent. */
        if (ANativeWindow_getWidth(window)>0 && ANativeWindow_getHeight(window)>0)
            return kernix_swapchain_probe_once_v1(window,report);
    }
    return result;
}
