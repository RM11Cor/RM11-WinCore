#include <jni.h>
#include "compiled_shaders.h"
#include <vulkan/vulkan.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool ok, const char* message) { if(!ok) throw std::runtime_error(message); }
void vkcheck(VkResult r, const char* name) {
    if(r != VK_SUCCESS) throw std::runtime_error(std::string(name)+" VkResult="+std::to_string(r));
}
uint32_t u32(const std::vector<uint8_t>& b, size_t pos) {
    require(pos <= b.size() && b.size()-pos>=4,"Truncated texture metadata");
    return uint32_t(b[pos]) | (uint32_t(b[pos+1])<<8) | (uint32_t(b[pos+2])<<16) | (uint32_t(b[pos+3])<<24);
}
bool magic(const std::vector<uint8_t>& b,size_t offset,const char* s) {
    return offset<=b.size() && b.size()-offset>=4 && std::memcmp(b.data()+offset,s,4)==0;
}
size_t alignUp(size_t n,size_t a) {
    require(a && !(a&(a-1)),"Invalid Vulkan buffer offset alignment");
    require(n<=SIZE_MAX-(a-1),"Staging offset overflow");
    return (n+a-1)&~(a-1);
}
struct Region {uint32_t level,w,h; size_t src,offset,bytes;};
struct Texture {
    uint32_t width=0,height=0,mips=0,encoding=0;
    VkFormat format=VK_FORMAT_UNDEFINED;
    std::string formatName;
    size_t payload=0,payloadSize=0;
    std::vector<Region> regions;
};
Texture parse(const std::vector<uint8_t>& b) {
    require(b.size()>=140 && b.size()<=16*1024*1024,"Invalid swatch size");
    require(magic(b,0,"burG") && u32(b,0x0c)==b.size(),"Invalid Grub bundle");
    require(u32(b,0x10)==1 && magic(b,0x14,"BCXT"),"Unsupported texture container");
    size_t meta=u32(b,0x1c), data=u32(b,0x20), packed=u32(b,0x24), unpacked=u32(b,0x28);
    require(meta<=b.size() && b.size()-meta>=0x4c && magic(b,meta,"HCXT"),"Missing TXCH metadata");
    require(data>=meta+0x4c && data<=b.size() && packed==unpacked && packed==b.size()-data,
        "Unsupported texture packing or offsets");
    Texture t;
    t.width=u32(b,meta+0x20);
    t.height=u32(b,meta+0x24);
    t.mips=b[meta+0x2e];
    t.encoding=u32(b,meta+0x48);
    t.payload=data; t.payloadSize=packed;
    require(t.width>0 && t.width<=8192 && t.height>0 && t.height<=8192 &&
        t.mips>=1 && t.mips<=16,"Texture dimensions or mip count invalid");
    uint32_t unit=0;
    switch(t.encoding) {
        case 9: t.format=VK_FORMAT_BC7_UNORM_BLOCK; t.formatName="BC7_UNORM";unit=16; break;
        case 11: t.format=VK_FORMAT_R16G16B16A16_UNORM; t.formatName="RGBA16_UNORM";unit=8;break;
        case 19: t.format=VK_FORMAT_R8_UNORM;t.formatName="R8_UNORM";unit=1;break;
        default: throw std::runtime_error("Unsupported TXCH encoding ID "+std::to_string(t.encoding));
    }
    size_t pos=0;
    for(uint32_t i=0;i<t.mips;++i) {
        uint32_t w=std::max(1u,t.width>>i),h=std::max(1u,t.height>>i);
        size_t units=(t.encoding==9)?
            size_t((w+3)/4)*size_t((h+3)/4):size_t(w)*h;
        size_t n=units*unit;
        require(pos<=packed && n<=packed-pos,"Mip payload is truncated");
        t.regions.push_back({i,w,h,pos,0,n});
        pos+=n;
    }
    require(pos==packed,"Mip payload length mismatch");
    return t;
}
struct Resources {
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkBuffer buffer=VK_NULL_HANDLE;
    VkDeviceMemory bufferMemory=VK_NULL_HANDLE;
    VkImage image=VK_NULL_HANDLE;
    VkDeviceMemory imageMemory=VK_NULL_HANDLE;
    VkImageView view=VK_NULL_HANDLE;
    VkSampler sampler=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    ~Resources(){
        if(device) {
            if(sampler)vkDestroySampler(device,sampler,nullptr);
            if(view)vkDestroyImageView(device,view,nullptr);
            if(pool)vkDestroyCommandPool(device,pool,nullptr);
            if(image)vkDestroyImage(device,image,nullptr);
            if(imageMemory)vkFreeMemory(device,imageMemory,nullptr);
            if(buffer)vkDestroyBuffer(device,buffer,nullptr);
            if(bufferMemory)vkFreeMemory(device,bufferMemory,nullptr);
            vkDestroyDevice(device,nullptr);
        }
        if(instance) vkDestroyInstance(instance,nullptr);
    }
};
uint32_t chooseMemory(VkPhysicalDevice gpu,uint32_t bits,VkMemoryPropertyFlags desired) {
    VkPhysicalDeviceMemoryProperties mem{};
    vkGetPhysicalDeviceMemoryProperties(gpu,&mem);
    for(uint32_t i=0;i<mem.memoryTypeCount;++i) {
        if((bits & (1u<<i)) && ((mem.memoryTypes[i].propertyFlags&desired)==desired))return i;
    }
    throw std::runtime_error("No required Vulkan memory type");
}
#include "vulkan_render_impl.h"
std::string upload(const std::vector<uint8_t>& bytes,std::vector<uint32_t>* preview=nullptr){
    Texture t=parse(bytes);
    Resources res;
    VkApplicationInfo app{};app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName="FH5 M20 GPU upload";app.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo ici{};ici.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;ici.pApplicationInfo=&app;
    vkcheck(vkCreateInstance(&ici,nullptr,&res.instance),"vkCreateInstance");
    uint32_t count=0;
    vkcheck(vkEnumeratePhysicalDevices(res.instance,&count,nullptr),"GPU enumeration");
    require(count>0,"No Vulkan GPU");
    std::vector<VkPhysicalDevice> gpus(count);
    vkcheck(vkEnumeratePhysicalDevices(res.instance,&count,gpus.data()),"GPU enumeration list");
    VkPhysicalDevice gpu=gpus[0];
    VkPhysicalDeviceProperties props{};
    VkPhysicalDeviceFeatures features{};
    vkGetPhysicalDeviceProperties(gpu,&props);
    vkGetPhysicalDeviceFeatures(gpu,&features);
    if(t.encoding==9) require(features.textureCompressionBC,"BC7 feature unavailable");
    VkFormatProperties formatProps{};
    vkGetPhysicalDeviceFormatProperties(gpu,t.format,&formatProps);
    require((formatProps.optimalTilingFeatures&VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT)!=0,
        "GPU cannot sample this format");
    VkImageFormatProperties caps{};
    vkcheck(vkGetPhysicalDeviceImageFormatProperties(gpu,t.format,VK_IMAGE_TYPE_2D,
        VK_IMAGE_TILING_OPTIMAL,VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT,0,&caps),
        "vkGetPhysicalDeviceImageFormatProperties");
    require(t.width<=caps.maxExtent.width && t.height<=caps.maxExtent.height &&
        t.mips<=caps.maxMipLevels,"GPU image size limit exceeded");
    uint32_t familyCount=0;
    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,nullptr);
    std::vector<VkQueueFamilyProperties> families(familyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,families.data());
    uint32_t family=UINT32_MAX;
    for(uint32_t i=0;i<familyCount;++i) if(families[i].queueCount &&
        (families[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)){family=i;break;}
    require(family!=UINT32_MAX,"No graphics queue");

    size_t alignment=std::max<size_t>(
        (t.encoding==9)?16:((t.encoding==11)?8:4),
        std::max<VkDeviceSize>(1,props.limits.optimalBufferCopyOffsetAlignment));
    size_t stagingSize=0;
    for(auto& r:t.regions) {
        stagingSize=alignUp(stagingSize,alignment);
        r.offset=stagingSize;
        require(r.bytes<=64*1024*1024-stagingSize,"Staging size limit");
        stagingSize+=r.bytes;
    }
    std::vector<uint8_t> stage(stagingSize,0);
    for(const auto& r:t.regions)
        std::memcpy(stage.data()+r.offset,bytes.data()+t.payload+r.src,r.bytes);

    float priority=1.0f;
    VkDeviceQueueCreateInfo qi{};qi.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qi.queueFamilyIndex=family;qi.queueCount=1;qi.pQueuePriorities=&priority;
    VkPhysicalDeviceFeatures required{};
    if(t.encoding==9)required.textureCompressionBC=VK_TRUE;
    VkDeviceCreateInfo dc{};dc.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dc.queueCreateInfoCount=1;dc.pQueueCreateInfos=&qi;dc.pEnabledFeatures=&required;
    vkcheck(vkCreateDevice(gpu,&dc,nullptr,&res.device),"vkCreateDevice");
    VkQueue queue=VK_NULL_HANDLE;
    vkGetDeviceQueue(res.device,family,0,&queue);

    VkBufferCreateInfo bi{};bi.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size=stagingSize;bi.usage=VK_BUFFER_USAGE_TRANSFER_SRC_BIT;bi.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    vkcheck(vkCreateBuffer(res.device,&bi,nullptr,&res.buffer),"vkCreateBuffer");
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(res.device,res.buffer,&mr);
    VkMemoryAllocateInfo ma{};ma.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ma.allocationSize=mr.size;
    ma.memoryTypeIndex=chooseMemory(gpu,mr.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    vkcheck(vkAllocateMemory(res.device,&ma,nullptr,&res.bufferMemory),"vkAllocateMemory staging");
    vkcheck(vkBindBufferMemory(res.device,res.buffer,res.bufferMemory,0),"vkBindBufferMemory staging");
    void* mapped=nullptr;
    vkcheck(vkMapMemory(res.device,res.bufferMemory,0,stagingSize,0,&mapped),"vkMapMemory");
    std::memcpy(mapped,stage.data(),stagingSize);
    vkUnmapMemory(res.device,res.bufferMemory);

    VkImageCreateInfo ii{};ii.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    ii.imageType=VK_IMAGE_TYPE_2D;ii.extent={t.width,t.height,1};
    ii.mipLevels=t.mips;ii.arrayLayers=1;ii.format=t.format;
    ii.tiling=VK_IMAGE_TILING_OPTIMAL;
    ii.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    ii.usage=VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT;
    ii.samples=VK_SAMPLE_COUNT_1_BIT;ii.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    vkcheck(vkCreateImage(res.device,&ii,nullptr,&res.image),"vkCreateImage");
    vkGetImageMemoryRequirements(res.device,res.image,&mr);
    ma.allocationSize=mr.size;
    ma.memoryTypeIndex=chooseMemory(gpu,mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    vkcheck(vkAllocateMemory(res.device,&ma,nullptr,&res.imageMemory),"vkAllocateMemory image");
    vkcheck(vkBindImageMemory(res.device,res.image,res.imageMemory,0),"vkBindImageMemory");

    VkCommandPoolCreateInfo pi{};pi.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pi.queueFamilyIndex=family;
    vkcheck(vkCreateCommandPool(res.device,&pi,nullptr,&res.pool),"vkCreateCommandPool");
    VkCommandBufferAllocateInfo ai{};ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool=res.pool;ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;ai.commandBufferCount=1;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    vkcheck(vkAllocateCommandBuffers(res.device,&ai,&cmd),"vkAllocateCommandBuffers");
    VkCommandBufferBeginInfo begin{};begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkcheck(vkBeginCommandBuffer(cmd,&begin),"vkBeginCommandBuffer");

    VkImageMemoryBarrier barrier{};barrier.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    barrier.oldLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    barrier.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    barrier.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    barrier.image=res.image;
    barrier.subresourceRange.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    barrier.subresourceRange.levelCount=t.mips;
    barrier.subresourceRange.layerCount=1;
    barrier.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,
        0,0,nullptr,0,nullptr,1,&barrier);

    std::vector<VkBufferImageCopy> copies;
    for(const auto& r:t.regions) {
        VkBufferImageCopy copy{};copy.bufferOffset=r.offset;
        copy.imageSubresource.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
        copy.imageSubresource.mipLevel=r.level;
        copy.imageSubresource.layerCount=1;
        copy.imageExtent={r.w,r.h,1};
        copies.push_back(copy);
    }
    vkCmdCopyBufferToImage(cmd,res.buffer,res.image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        uint32_t(copies.size()),copies.data());
    barrier.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    barrier.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
    vkCmdPipelineBarrier(cmd,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
        0,0,nullptr,0,nullptr,1,&barrier);
    vkcheck(vkEndCommandBuffer(cmd),"vkEndCommandBuffer");
    VkSubmitInfo submit{};submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount=1;submit.pCommandBuffers=&cmd;
    vkcheck(vkQueueSubmit(queue,1,&submit,VK_NULL_HANDLE),"vkQueueSubmit");
    vkcheck(vkQueueWaitIdle(queue),"vkQueueWaitIdle");

    VkImageViewCreateInfo vi{};vi.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    vi.image=res.image;vi.viewType=VK_IMAGE_VIEW_TYPE_2D;vi.format=t.format;
    vi.subresourceRange.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    vi.subresourceRange.levelCount=t.mips;vi.subresourceRange.layerCount=1;
    vkcheck(vkCreateImageView(res.device,&vi,nullptr,&res.view),"vkCreateImageView");
    VkSamplerCreateInfo si{};si.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
    si.magFilter=VK_FILTER_NEAREST;si.minFilter=VK_FILTER_NEAREST;
    si.mipmapMode=VK_SAMPLER_MIPMAP_MODE_NEAREST;
    si.addressModeU=si.addressModeV=si.addressModeW=VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
    si.maxLod=float(t.mips);
    vkcheck(vkCreateSampler(res.device,&si,nullptr,&res.sampler),"vkCreateSampler");
    if(preview) renderTexture(res,gpu,queue,family,t,*preview);
    std::ostringstream out;
    out<<"PASS: "<<t.formatName<<" "<<t.width<<"x"<<t.height
        <<", "<<t.mips<<" mip(s); "<<stagingSize<<" staging bytes"
        <<"\nGPU queue completed; Vulkan image, view and sampler created.";
    return out.str();
}
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_r4_fh5probe_MainActivity_nativeUploadSwatch(JNIEnv* env,jclass,jbyteArray arr){
    try {
        if(!arr) throw std::runtime_error("Missing texture input");
        jsize len=env->GetArrayLength(arr);
        if(len<140 || len>16*1024*1024)throw std::runtime_error("Swatch file size out of range");
        std::vector<uint8_t> b(static_cast<size_t>(len));
        env->GetByteArrayRegion(arr,0,len,reinterpret_cast<jbyte*>(b.data()));
        if(env->ExceptionCheck()) return nullptr;
        std::string result=upload(b);
        return env->NewStringUTF(result.c_str());
    } catch(const std::exception& ex) {
        std::string message=std::string("FAIL: ")+ex.what();
        return env->NewStringUTF(message.c_str());
    }
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_r4_fh5probe_MainActivity_nativeRenderSwatch(JNIEnv* env,jclass,jbyteArray arr){
    try {
        if(!arr)throw std::runtime_error("Texture input is null");
        jsize len=env->GetArrayLength(arr);
        if(len<140 || len>16*1024*1024)throw std::runtime_error("Texture size invalid");
        std::vector<uint8_t> b(static_cast<size_t>(len));
        env->GetByteArrayRegion(arr,0,len,reinterpret_cast<jbyte*>(b.data()));
        if(env->ExceptionCheck())return nullptr;
        std::vector<uint32_t> pixels;
        upload(b,&pixels);
        if(pixels.size()<3 || pixels.size()>size_t(INT32_MAX))
            throw std::runtime_error("Invalid render output");
        jintArray result=env->NewIntArray(static_cast<jsize>(pixels.size()));
        if(!result)return nullptr;
        env->SetIntArrayRegion(result,0,static_cast<jsize>(pixels.size()),
            reinterpret_cast<const jint*>(pixels.data()));
        return result;
    }catch(const std::exception& e){
        jclass clazz=env->FindClass("java/lang/RuntimeException");
        if(clazz)env->ThrowNew(clazz,e.what());
        return nullptr;
    }
}
