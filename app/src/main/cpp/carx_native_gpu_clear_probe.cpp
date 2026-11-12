// Original independent Android Vulkan GPU command/readback probe.
// This is NOT original CarX game logic, and does NOT load game assets.
// The output is a real VkDevice + VkQueue + GPU clear + transfer + CPU readback.
#include <jni.h>
#include <vulkan/vulkan.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr uint32_t WIDTH=32;
constexpr uint32_t HEIGHT=32;
constexpr VkDeviceSize BYTES=WIDTH*HEIGHT*4;

struct Handles {
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkImage image=VK_NULL_HANDLE;
    VkDeviceMemory imageMemory=VK_NULL_HANDLE;
    VkBuffer buffer=VK_NULL_HANDLE;
    VkDeviceMemory bufferMemory=VK_NULL_HANDLE;
    VkCommandPool commandPool=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    bool submitted=false;
    bool fenceWaited=false;

    ~Handles() {
        if(device!=VK_NULL_HANDLE) {
            if(submitted && !fenceWaited) {
                // Defensive cleanup, not a performance benchmark.
                vkDeviceWaitIdle(device);
            }
            if(fence!=VK_NULL_HANDLE)vkDestroyFence(device,fence,nullptr);
            if(commandPool!=VK_NULL_HANDLE)vkDestroyCommandPool(device,commandPool,nullptr);
            if(buffer!=VK_NULL_HANDLE)vkDestroyBuffer(device,buffer,nullptr);
            if(bufferMemory!=VK_NULL_HANDLE)vkFreeMemory(device,bufferMemory,nullptr);
            if(image!=VK_NULL_HANDLE)vkDestroyImage(device,image,nullptr);
            if(imageMemory!=VK_NULL_HANDLE)vkFreeMemory(device,imageMemory,nullptr);
            vkDestroyDevice(device,nullptr);
        }
        if(instance!=VK_NULL_HANDLE)vkDestroyInstance(instance,nullptr);
    }
};
bool memoryType(const VkPhysicalDeviceMemoryProperties& props,
                uint32_t allowed,VkMemoryPropertyFlags required,uint32_t& found) {
    for(uint32_t i=0;i<props.memoryTypeCount;i++) {
        if((allowed&(1U<<i)) &&
           (props.memoryTypes[i].propertyFlags&required)==required) {
            found=i;
            return true;
        }
    }
    return false;
}
bool approximate(uint8_t v,int target) {
    return std::abs(static_cast<int>(v)-target)<=2;
}
std::string perform() {
    Handles h;
    const char* stage="initializing";
    VkResult code=VK_SUCCESS;
    bool gpuSubmitted=false;
    bool fenceCompleted=false;
    bool allPixelsCorrect=false;
    bool gotReadback=false;
    int pixel[4]={-1,-1,-1,-1};
    uint32_t queueFamily=UINT32_MAX;
    bool deviceCreated=false;
    bool imageCreated=false;

    // Report stages and genuine VkResult; no synthetic success can be returned.
    do {
        stage="vkCreateInstance";
        VkApplicationInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
        ai.pApplicationName="Original PortLab GPU offscreen readback, NOT CarX game";
        ai.apiVersion=VK_API_VERSION_1_0;
        VkInstanceCreateInfo ici{};
        ici.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ici.pApplicationInfo=&ai;
        code=vkCreateInstance(&ici,nullptr,&h.instance);
        if(code!=VK_SUCCESS)break;

        stage="vkEnumeratePhysicalDevices";
        uint32_t gpuCount=0;
        code=vkEnumeratePhysicalDevices(h.instance,&gpuCount,nullptr);
        if(code!=VK_SUCCESS)break;
        if(gpuCount==0||gpuCount>16){code=VK_ERROR_INITIALIZATION_FAILED;break;}
        std::vector<VkPhysicalDevice> gpus(gpuCount);
        code=vkEnumeratePhysicalDevices(h.instance,&gpuCount,gpus.data());
        if(code!=VK_SUCCESS)break;
        VkPhysicalDevice gpu=gpus[0];

        stage="graphics_queue_family";
        uint32_t familyCount=0;
        vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,nullptr);
        if(familyCount==0||familyCount>64){code=VK_ERROR_INITIALIZATION_FAILED;break;}
        std::vector<VkQueueFamilyProperties> families(familyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,families.data());
        for(uint32_t i=0;i<familyCount;i++){
            if((families[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)!=0 &&
               families[i].queueCount>0){queueFamily=i;break;}
        }
        if(queueFamily==UINT32_MAX){code=VK_ERROR_FEATURE_NOT_PRESENT;break;}

        stage="vkCreateDevice";
        float priority=1.f;
        VkDeviceQueueCreateInfo qci{};
        qci.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex=queueFamily;
        qci.queueCount=1;
        qci.pQueuePriorities=&priority;
        VkDeviceCreateInfo dci{};
        dci.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount=1;
        dci.pQueueCreateInfos=&qci;
        code=vkCreateDevice(gpu,&dci,nullptr,&h.device);
        if(code!=VK_SUCCESS)break;
        deviceCreated=true;
        VkQueue queue=VK_NULL_HANDLE;
        vkGetDeviceQueue(h.device,queueFamily,0,&queue);
        if(queue==VK_NULL_HANDLE){code=VK_ERROR_INITIALIZATION_FAILED;break;}
        VkPhysicalDeviceMemoryProperties memory{};
        vkGetPhysicalDeviceMemoryProperties(gpu,&memory);
        VkFormatProperties formatProps{};
        vkGetPhysicalDeviceFormatProperties(gpu,VK_FORMAT_R8G8B8A8_UNORM,&formatProps);
        const VkFormatFeatureFlags requiredFormat=
                VK_FORMAT_FEATURE_TRANSFER_SRC_BIT | VK_FORMAT_FEATURE_TRANSFER_DST_BIT;
        if((formatProps.optimalTilingFeatures&requiredFormat)!=requiredFormat){
            stage="RGBA8_optimal_transfer_support";
            code=VK_ERROR_FORMAT_NOT_SUPPORTED;
            break;
        }

        stage="vkCreateImage";
        VkImageCreateInfo im{};
        im.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
        im.imageType=VK_IMAGE_TYPE_2D;
        im.format=VK_FORMAT_R8G8B8A8_UNORM;
        im.extent={WIDTH,HEIGHT,1};
        im.mipLevels=1;
        im.arrayLayers=1;
        im.samples=VK_SAMPLE_COUNT_1_BIT;
        im.tiling=VK_IMAGE_TILING_OPTIMAL;
        im.usage=VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
        im.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        im.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
        code=vkCreateImage(h.device,&im,nullptr,&h.image);
        if(code!=VK_SUCCESS)break;
        imageCreated=true;
        VkMemoryRequirements imReq{};
        vkGetImageMemoryRequirements(h.device,h.image,&imReq);
        uint32_t imType=0;
        if(!memoryType(memory,imReq.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,imType) &&
           !memoryType(memory,imReq.memoryTypeBits,0,imType)){
            stage="image_memory_type";
            code=VK_ERROR_FEATURE_NOT_PRESENT;
            break;
        }
        VkMemoryAllocateInfo alloc{};
        alloc.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
        alloc.allocationSize=imReq.size;
        alloc.memoryTypeIndex=imType;
        stage="image_memory_allocate";
        code=vkAllocateMemory(h.device,&alloc,nullptr,&h.imageMemory);
        if(code!=VK_SUCCESS)break;
        code=vkBindImageMemory(h.device,h.image,h.imageMemory,0);
        if(code!=VK_SUCCESS){stage="vkBindImageMemory";break;}

        stage="vkCreateBuffer";
        VkBufferCreateInfo bi{};
        bi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
        bi.size=BYTES;
        bi.usage=VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        bi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
        code=vkCreateBuffer(h.device,&bi,nullptr,&h.buffer);
        if(code!=VK_SUCCESS)break;
        VkMemoryRequirements bufReq{};
        vkGetBufferMemoryRequirements(h.device,h.buffer,&bufReq);
        uint32_t bufType=0;
        if(!memoryType(memory,bufReq.memoryTypeBits,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,bufType) &&
           !memoryType(memory,bufReq.memoryTypeBits,VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
                      bufType)){
            stage="host_readback_memory_type";
            code=VK_ERROR_FEATURE_NOT_PRESENT;
            break;
        }
        VkMemoryPropertyFlags bufFlags=memory.memoryTypes[bufType].propertyFlags;
        alloc.allocationSize=bufReq.size;
        alloc.memoryTypeIndex=bufType;
        stage="host_readback_memory_allocate";
        code=vkAllocateMemory(h.device,&alloc,nullptr,&h.bufferMemory);
        if(code!=VK_SUCCESS)break;
        code=vkBindBufferMemory(h.device,h.buffer,h.bufferMemory,0);
        if(code!=VK_SUCCESS){stage="vkBindBufferMemory";break;}

        stage="vkCreateCommandPool";
        VkCommandPoolCreateInfo pci{};
        pci.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        pci.queueFamilyIndex=queueFamily;
        code=vkCreateCommandPool(h.device,&pci,nullptr,&h.commandPool);
        if(code!=VK_SUCCESS)break;
        VkCommandBuffer cmd=VK_NULL_HANDLE;
        VkCommandBufferAllocateInfo cbi{};
        cbi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        cbi.commandPool=h.commandPool;
        cbi.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cbi.commandBufferCount=1;
        stage="vkAllocateCommandBuffers";
        code=vkAllocateCommandBuffers(h.device,&cbi,&cmd);
        if(code!=VK_SUCCESS)break;
        VkCommandBufferBeginInfo begin{};
        begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        stage="vkBeginCommandBuffer";
        code=vkBeginCommandBuffer(cmd,&begin);
        if(code!=VK_SUCCESS)break;

        VkImageMemoryBarrier toClear{};
        toClear.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
        toClear.oldLayout=VK_IMAGE_LAYOUT_UNDEFINED;
        toClear.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        toClear.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
        toClear.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
        toClear.image=h.image;
        toClear.subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
        toClear.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,nullptr,0,nullptr,
                             1,&toClear);

        const VkClearColorValue clear={{0.2f,0.5f,0.8f,1.0f}};
        const VkImageSubresourceRange range={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
        vkCmdClearColorImage(cmd,h.image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                             &clear,1,&range);

        VkImageMemoryBarrier toRead=toClear;
        toRead.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        toRead.newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
        toRead.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        toRead.dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
        vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,nullptr,0,nullptr,
                             1,&toRead);
        VkBufferImageCopy copy{};
        copy.imageSubresource={VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};
        copy.imageExtent={WIDTH,HEIGHT,1};
        vkCmdCopyImageToBuffer(cmd,h.image,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                               h.buffer,1,&copy);

        VkBufferMemoryBarrier toHost{};
        toHost.sType=VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        toHost.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
        toHost.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
        toHost.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
        toHost.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
        toHost.buffer=h.buffer;
        toHost.offset=0;
        toHost.size=BYTES;
        vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_HOST_BIT,0,0,nullptr,1,&toHost,0,nullptr);

        stage="vkEndCommandBuffer";
        code=vkEndCommandBuffer(cmd);
        if(code!=VK_SUCCESS)break;
        VkFenceCreateInfo fci{};
        fci.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        stage="vkCreateFence";
        code=vkCreateFence(h.device,&fci,nullptr,&h.fence);
        if(code!=VK_SUCCESS)break;
        VkSubmitInfo submit{};
        submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submit.commandBufferCount=1;
        submit.pCommandBuffers=&cmd;
        stage="vkQueueSubmit";
        code=vkQueueSubmit(queue,1,&submit,h.fence);
        if(code!=VK_SUCCESS)break;
        h.submitted=true;
        gpuSubmitted=true;

        stage="vkWaitForFences";
        code=vkWaitForFences(h.device,1,&h.fence,VK_TRUE,4'000'000'000ULL);
        if(code!=VK_SUCCESS)break;
        h.fenceWaited=true;
        fenceCompleted=true;

        stage="vkMapMemory";
        void* mapped=nullptr;
        code=vkMapMemory(h.device,h.bufferMemory,0,VK_WHOLE_SIZE,0,&mapped);
        if(code!=VK_SUCCESS)break;
        bool invalidationOk=true;
        if((bufFlags&VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)==0) {
            VkMappedMemoryRange mr{};
            mr.sType=VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
            mr.memory=h.bufferMemory;
            mr.offset=0;
            mr.size=VK_WHOLE_SIZE; // entire allocation avoids atom-size errors
            code=vkInvalidateMappedMemoryRanges(h.device,1,&mr);
            invalidationOk=(code==VK_SUCCESS);
        }
        if(invalidationOk) {
            const auto* read=static_cast<const uint8_t*>(mapped);
            for(int i=0;i<4;i++)pixel[i]=read[i];
            gotReadback=true;
            allPixelsCorrect=true;
            for(uint32_t i=0;i<WIDTH*HEIGHT;i++) {
                const uint32_t off=4*i;
                if(!approximate(read[off],51) ||
                   !approximate(read[off+1],128) ||
                   !approximate(read[off+2],204) ||
                   !approximate(read[off+3],255)){
                    allPixelsCorrect=false;
                    break;
                }
            }
            stage=allPixelsCorrect?"complete_verified_gpu_offscreen_clear":
                "gpu_pixel_mismatch";
            if(!allPixelsCorrect)code=VK_ERROR_FORMAT_NOT_SUPPORTED;
        } else {
            stage="vkInvalidateMappedMemoryRanges";
        }
        vkUnmapMemory(h.device,h.bufferMemory);
    } while(false);

    std::ostringstream o;
    o<<"{\"schema\":\"rm11carx.vulkan-offscreen-clear-readback.v1\",";
#if defined(__aarch64__)
    o<<"\"actual_arm64_native_function_executed\":true,";
#else
    o<<"\"actual_arm64_native_function_executed\":false,";
#endif
    o<<"\"stage\":\""<<stage<<"\",";
    o<<"\"vk_result\":"<<static_cast<int>(code)<<",";
    o<<"\"vk_device_created\":"<<(deviceCreated?"true":"false")<<",";
    o<<"\"rgba8_gpu_image_created\":"<<(imageCreated?"true":"false")<<",";
    o<<"\"graphics_queue_family_index\":";
    if(queueFamily==UINT32_MAX)o<<"null,";
    else o<<queueFamily<<",";
    o<<"\"command_buffer_submitted_to_gpu\":"<<(gpuSubmitted?"true":"false")<<",";
    o<<"\"gpu_fence_completed\":"<<(fenceCompleted?"true":"false")<<",";
    o<<"\"host_readback_completed\":"<<(gotReadback?"true":"false")<<",";
    o<<"\"expected_clear_rgba8\":[51,128,204,255],";
    o<<"\"readback_first_rgba8\":["<<pixel[0]<<","<<pixel[1]<<","<<pixel[2]<<","<<pixel[3]<<"],";
    o<<"\"all_1024_pixels_match_clear_color\":"<<(allPixelsCorrect?"true":"false")<<",";
    o<<"\"native_gpu_offscreen_clear_and_readback_proven\":"
       <<((fenceCompleted && gotReadback && allPixelsCorrect)?"true":"false")<<",";
    o<<"\"real_android_surface_created\":false,";
    o<<"\"real_android_swapchain_created\":false,";
    o<<"\"carx_game_logic_executed\":false,";
    o<<"\"original_carx_game_frame_rendered\":false,";
    o<<"\"original_unity_6000_3_8f1_android_runtime_present\":false,";
    o<<"\"windows_standalone_asset_compatibility_proven\":false}";
    return o.str();
}
} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_rm11cor_carxstreet_portlab_NativeVulkanProbe_probeNativeGpuClear(
        JNIEnv* env, jclass) {
    const std::string result=perform();
    return env->NewStringUTF(result.c_str());
}
