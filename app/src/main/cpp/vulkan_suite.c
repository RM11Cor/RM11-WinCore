#define VK_USE_PLATFORM_ANDROID_KHR 1
#include <jni.h>
#include <android/native_window_jni.h>
#include <android/native_window.h>
#include <vulkan/vulkan.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rm11_shaders_generated.h"

/* RM11-WinCore 2.4.12: on-device Vulkan GPU test; no Wine/DXVK is executed. */
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}
static uint32_t clamp_uint(uint32_t x, uint32_t a, uint32_t b) {
    return x < a ? a : (x > b ? b : x);
}
static VkCompositeAlphaFlagBitsKHR alpha_choice(VkCompositeAlphaFlagsKHR flags) {
    const VkCompositeAlphaFlagBitsKHR modes[] = { VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR,
        VK_COMPOSITE_ALPHA_PRE_MULTIPLIED_BIT_KHR, VK_COMPOSITE_ALPHA_POST_MULTIPLIED_BIT_KHR,
        VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR };
    for (uint32_t i=0;i<4;i++) if ((flags&modes[i])!=0) return modes[i];
    return VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
}
static uint32_t choose_memory(VkPhysicalDevice p, uint32_t typebits, VkMemoryPropertyFlags need) {
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(p, &mp);
    for(uint32_t i=0; i<mp.memoryTypeCount; i++) {
        if ((typebits & (1u<<i)) && (mp.memoryTypes[i].propertyFlags & need)==need) return i;
    }
    return UINT32_MAX;
}
static bool device_has_ext(VkPhysicalDevice p, const char *needle) {
    uint32_t n = 0;
    if(vkEnumerateDeviceExtensionProperties(p,NULL,&n,NULL)!=VK_SUCCESS) return false;
    VkExtensionProperties *list=(VkExtensionProperties*)calloc(n+1,sizeof(*list));
    if(!list) return false;
    VkResult rc=vkEnumerateDeviceExtensionProperties(p,NULL,&n,list);
    bool found=false;
    if(rc==VK_SUCCESS) for(uint32_t i=0;i<n;i++) if(strcmp(list[i].extensionName,needle)==0) found=true;
    free(list);
    return found;
}

JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_VulkanSuite_nativeRun(JNIEnv *env, jclass cls, jobject surfaceObj) {
    (void)cls;
    const char *stage="startup";
    VkResult rc=VK_SUCCESS;
    char gpu[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE]="unknown";
    char result[2500];
    bool shaders=false, triangle=false, compute=false, timestamps=false, timestampValid=false;
    bool extDescriptor=false, extTimeline=false, extMemoryBudget=false;
    int computeMismatches=-1;
    uint32_t frames=0, width=0, height=0, graphicFamily=UINT32_MAX, presentFamily=UINT32_MAX;
    float gpuTimeMs=0.0f;
    double measuredFps=0.0, wallFrameMs=0.0;
    ANativeWindow *window=NULL;
    VkInstance instance=VK_NULL_HANDLE;
    VkSurfaceKHR surface=VK_NULL_HANDLE;
    VkPhysicalDevice physical=VK_NULL_HANDLE;
    VkDevice device=VK_NULL_HANDLE;
    VkQueue queue=VK_NULL_HANDLE, presentQueue=VK_NULL_HANDLE;
    VkSwapchainKHR swapchain=VK_NULL_HANDLE;
    VkImage *images=NULL;
    VkImageView *views=NULL;
    VkFramebuffer *framebuffers=NULL;
    uint32_t imageCount=0;
    VkRenderPass renderPass=VK_NULL_HANDLE;
    VkShaderModule vert=VK_NULL_HANDLE, frag=VK_NULL_HANDLE, comp=VK_NULL_HANDLE;
    VkPipelineLayout gfxLayout=VK_NULL_HANDLE, compLayout=VK_NULL_HANDLE;
    VkPipeline gfxPipeline=VK_NULL_HANDLE, compPipeline=VK_NULL_HANDLE;
    VkCommandPool pool=VK_NULL_HANDLE;
    VkCommandBuffer cmd=VK_NULL_HANDLE;
    VkSemaphore ready=VK_NULL_HANDLE, drawn=VK_NULL_HANDLE;
    VkFence fence=VK_NULL_HANDLE;
    VkQueryPool queryPool=VK_NULL_HANDLE;
    VkBuffer computeBuffer=VK_NULL_HANDLE;
    VkDeviceMemory computeMemory=VK_NULL_HANDLE;
    VkDescriptorSetLayout setLayout=VK_NULL_HANDLE;
    VkDescriptorPool setPool=VK_NULL_HANDLE;
    VkDescriptorSet descriptor=VK_NULL_HANDLE;
    bool doCompute=false;
    VkPhysicalDeviceProperties props;
    memset(&props,0,sizeof(props));
#define CHECK(call, label) do { stage=label; rc=(call); if(rc!=VK_SUCCESS) goto done; } while(0)
    stage="ANativeWindow";
    window=ANativeWindow_fromSurface(env,surfaceObj);
    if(!window){rc=VK_ERROR_INITIALIZATION_FAILED;goto done;}
    const char *instanceExt[]={ VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME };
    VkApplicationInfo ai={ .sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName="RM11 GPU Five-Stage Suite", .apiVersion=VK_API_VERSION_1_0 };
    VkInstanceCreateInfo ici={ .sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo=&ai, .enabledExtensionCount=2, .ppEnabledExtensionNames=instanceExt };
    CHECK(vkCreateInstance(&ici,NULL,&instance),"vkCreateInstance");
    VkAndroidSurfaceCreateInfoKHR asci={ .sType=VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR,
        .window=window };
    CHECK(vkCreateAndroidSurfaceKHR(instance,&asci,NULL,&surface),"vkCreateAndroidSurfaceKHR");
    uint32_t ndev=0;
    CHECK(vkEnumeratePhysicalDevices(instance,&ndev,NULL),"vkEnumeratePhysicalDevices(count)");
    if(ndev==0){rc=VK_ERROR_INITIALIZATION_FAILED;stage="no physical device";goto done;}
    VkPhysicalDevice *choices=(VkPhysicalDevice*)calloc(ndev,sizeof(*choices));
    if(!choices){rc=VK_ERROR_OUT_OF_HOST_MEMORY;stage="gpu allocation";goto done;}
    rc=vkEnumeratePhysicalDevices(instance,&ndev,choices);
    if(rc==VK_SUCCESS) for(uint32_t d=0;d<ndev && !physical;d++) {
        if(!device_has_ext(choices[d],VK_KHR_SWAPCHAIN_EXTENSION_NAME)) continue;
        uint32_t nq=0;
        vkGetPhysicalDeviceQueueFamilyProperties(choices[d],&nq,NULL);
        VkQueueFamilyProperties *qprops=(VkQueueFamilyProperties*)calloc(nq+1,sizeof(*qprops));
        if(!qprops) continue;
        vkGetPhysicalDeviceQueueFamilyProperties(choices[d],&nq,qprops);
        uint32_t g=UINT32_MAX,p=UINT32_MAX;
        for(uint32_t i=0;i<nq;i++) {
            VkBool32 canPresent=VK_FALSE;
            if(vkGetPhysicalDeviceSurfaceSupportKHR(choices[d],i,surface,&canPresent)!=VK_SUCCESS)continue;
            if(qprops[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
                if(g==UINT32_MAX || (qprops[i].queueFlags&VK_QUEUE_COMPUTE_BIT))g=i;
            }
            if(canPresent) p=i;
            if(canPresent && (qprops[i].queueFlags&VK_QUEUE_GRAPHICS_BIT) &&
                 (qprops[i].queueFlags&VK_QUEUE_COMPUTE_BIT)) {g=p=i;break;}
        }
        free(qprops);
        if(g!=UINT32_MAX && p!=UINT32_MAX){physical=choices[d];graphicFamily=g;presentFamily=p;}
    }
    free(choices);
    if(!physical){rc=VK_ERROR_FEATURE_NOT_PRESENT;stage="no swapchain graphics+present GPU";goto done;}
    vkGetPhysicalDeviceProperties(physical,&props);
    snprintf(gpu,sizeof(gpu),"%s",props.deviceName);
    extDescriptor=device_has_ext(physical,"VK_EXT_descriptor_indexing") || VK_API_VERSION_MAJOR(props.apiVersion)>1 ||
        (VK_API_VERSION_MAJOR(props.apiVersion)==1 && VK_API_VERSION_MINOR(props.apiVersion)>=2);
    extTimeline=device_has_ext(physical,"VK_KHR_timeline_semaphore") || VK_API_VERSION_MAJOR(props.apiVersion)>1 ||
        (VK_API_VERSION_MAJOR(props.apiVersion)==1 && VK_API_VERSION_MINOR(props.apiVersion)>=2);
    extMemoryBudget=device_has_ext(physical,"VK_EXT_memory_budget");
    uint32_t nq=0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical,&nq,NULL);
    VkQueueFamilyProperties *properties=(VkQueueFamilyProperties*)calloc(nq+1,sizeof(*properties));
    if(!properties){rc=VK_ERROR_OUT_OF_HOST_MEMORY;stage="queue family properties";goto done;}
    vkGetPhysicalDeviceQueueFamilyProperties(physical,&nq,properties);
    doCompute=(properties[graphicFamily].queueFlags&VK_QUEUE_COMPUTE_BIT)!=0;
    timestamps=properties[graphicFamily].timestampValidBits>0;
    free(properties);
    float priority=1.0f;
    VkDeviceQueueCreateInfo qci[]={
        {.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, .queueFamilyIndex=graphicFamily,
          .queueCount=1,.pQueuePriorities=&priority},
        {.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,.queueFamilyIndex=presentFamily,
          .queueCount=1,.pQueuePriorities=&priority}
    };
    const char *swExt=VK_KHR_SWAPCHAIN_EXTENSION_NAME;
    VkDeviceCreateInfo dci={.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount=graphicFamily==presentFamily?1u:2u,.pQueueCreateInfos=qci,
        .enabledExtensionCount=1,.ppEnabledExtensionNames=&swExt};
    CHECK(vkCreateDevice(physical,&dci,NULL,&device),"vkCreateDevice");
    vkGetDeviceQueue(device,graphicFamily,0,&queue);
    vkGetDeviceQueue(device,presentFamily,0,&presentQueue);

    VkSurfaceCapabilitiesKHR caps;
    CHECK(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(physical,surface,&caps),"surfaceCapabilities");
    if(!(caps.supportedUsageFlags&VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT)){
        rc=VK_ERROR_FORMAT_NOT_SUPPORTED;stage="swapchain lacks COLOR_ATTACHMENT";goto done;
    }
    uint32_t nf=0;
    CHECK(vkGetPhysicalDeviceSurfaceFormatsKHR(physical,surface,&nf,NULL),"surfaceFormats(count)");
    if(nf==0){rc=VK_ERROR_FORMAT_NOT_SUPPORTED;stage="no surface formats";goto done;}
    VkSurfaceFormatKHR *formats=(VkSurfaceFormatKHR*)calloc(nf,sizeof(*formats));
    if(!formats){rc=VK_ERROR_OUT_OF_HOST_MEMORY;stage="surface formats allocation";goto done;}
    rc=vkGetPhysicalDeviceSurfaceFormatsKHR(physical,surface,&nf,formats);
    if(rc!=VK_SUCCESS){free(formats);stage="surfaceFormats(list)";goto done;}
    VkSurfaceFormatKHR fmt=formats[0];
    for(uint32_t i=0;i<nf;i++) if(formats[i].format==VK_FORMAT_R8G8B8A8_UNORM ||
        formats[i].format==VK_FORMAT_B8G8R8A8_UNORM){fmt=formats[i];break;}
    free(formats);
    if(fmt.format==VK_FORMAT_UNDEFINED)fmt.format=VK_FORMAT_R8G8B8A8_UNORM;
    VkExtent2D extent=caps.currentExtent;
    if(extent.width==UINT32_MAX){
        extent.width=clamp_uint((uint32_t)ANativeWindow_getWidth(window),caps.minImageExtent.width,caps.maxImageExtent.width);
        extent.height=clamp_uint((uint32_t)ANativeWindow_getHeight(window),caps.minImageExtent.height,caps.maxImageExtent.height);
    }
    if(!extent.width || !extent.height){rc=VK_ERROR_INITIALIZATION_FAILED;stage="zero surface extent";goto done;}
    width=extent.width;height=extent.height;
    uint32_t minCount=caps.minImageCount+1;
    if(caps.maxImageCount && minCount>caps.maxImageCount)minCount=caps.maxImageCount;
    uint32_t sharingFamilies[]={graphicFamily,presentFamily};
    VkSwapchainCreateInfoKHR sci={.sType=VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR,
        .surface=surface,.minImageCount=minCount,.imageFormat=fmt.format,
        .imageColorSpace=fmt.colorSpace,.imageExtent=extent,.imageArrayLayers=1,
        .imageUsage=VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
        .imageSharingMode=graphicFamily==presentFamily?VK_SHARING_MODE_EXCLUSIVE:VK_SHARING_MODE_CONCURRENT,
        .queueFamilyIndexCount=graphicFamily==presentFamily?0u:2u,
        .pQueueFamilyIndices=graphicFamily==presentFamily?NULL:sharingFamilies,
        .preTransform=caps.currentTransform,.compositeAlpha=alpha_choice(caps.supportedCompositeAlpha),
        .presentMode=VK_PRESENT_MODE_FIFO_KHR,.clipped=VK_TRUE};
    CHECK(vkCreateSwapchainKHR(device,&sci,NULL,&swapchain),"vkCreateSwapchainKHR");
    CHECK(vkGetSwapchainImagesKHR(device,swapchain,&imageCount,NULL),"swapchain images(count)");
    images=(VkImage*)calloc(imageCount,sizeof(*images));
    views=(VkImageView*)calloc(imageCount,sizeof(*views));
    framebuffers=(VkFramebuffer*)calloc(imageCount,sizeof(*framebuffers));
    if(!images || !views || !framebuffers){rc=VK_ERROR_OUT_OF_HOST_MEMORY;stage="swapchain image arrays";goto done;}
    CHECK(vkGetSwapchainImagesKHR(device,swapchain,&imageCount,images),"swapchain images(list)");
    for(uint32_t i=0;i<imageCount;i++){
        VkImageViewCreateInfo iv={.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
            .image=images[i],.viewType=VK_IMAGE_VIEW_TYPE_2D,.format=fmt.format,
            .subresourceRange={VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1}};
        CHECK(vkCreateImageView(device,&iv,NULL,&views[i]),"vkCreateImageView");
    }
    VkAttachmentDescription att={.format=fmt.format,.samples=VK_SAMPLE_COUNT_1_BIT,
        .loadOp=VK_ATTACHMENT_LOAD_OP_CLEAR,.storeOp=VK_ATTACHMENT_STORE_OP_STORE,
        .stencilLoadOp=VK_ATTACHMENT_LOAD_OP_DONT_CARE,.stencilStoreOp=VK_ATTACHMENT_STORE_OP_DONT_CARE,
        .initialLayout=VK_IMAGE_LAYOUT_UNDEFINED,.finalLayout=VK_IMAGE_LAYOUT_PRESENT_SRC_KHR};
    VkAttachmentReference ref={.attachment=0,.layout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkSubpassDescription sub={.pipelineBindPoint=VK_PIPELINE_BIND_POINT_GRAPHICS,
        .colorAttachmentCount=1,.pColorAttachments=&ref};
    VkSubpassDependency dep={.srcSubpass=VK_SUBPASS_EXTERNAL,.dstSubpass=0,
        .srcStageMask=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
        .dstStageMask=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
        .dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT};
    VkRenderPassCreateInfo rpci={.sType=VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
        .attachmentCount=1,.pAttachments=&att,.subpassCount=1,.pSubpasses=&sub,
        .dependencyCount=1,.pDependencies=&dep};
    CHECK(vkCreateRenderPass(device,&rpci,NULL,&renderPass),"vkCreateRenderPass");
    for(uint32_t i=0;i<imageCount;i++) {
        VkFramebufferCreateInfo fb={.sType=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
            .renderPass=renderPass,.attachmentCount=1,.pAttachments=&views[i],
            .width=width,.height=height,.layers=1};
        CHECK(vkCreateFramebuffer(device,&fb,NULL,&framebuffers[i]),"vkCreateFramebuffer");
    }

    VkShaderModuleCreateInfo vci={.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        .codeSize=sizeof(rm11_vert_spv),.pCode=rm11_vert_spv};
    VkShaderModuleCreateInfo fci={.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        .codeSize=sizeof(rm11_frag_spv),.pCode=rm11_frag_spv};
    CHECK(vkCreateShaderModule(device,&vci,NULL,&vert),"vertex vkCreateShaderModule");
    CHECK(vkCreateShaderModule(device,&fci,NULL,&frag),"fragment vkCreateShaderModule");
    shaders=true;
    VkPipelineShaderStageCreateInfo stages[]={
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_VERTEX_BIT,.module=vert,.pName="main"},
        {.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
         .stage=VK_SHADER_STAGE_FRAGMENT_BIT,.module=frag,.pName="main"}
    };
    VkPipelineVertexInputStateCreateInfo vertex={.sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
    VkPipelineInputAssemblyStateCreateInfo assembly={.sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO,
        .topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST};
    VkViewport viewport={0,0,(float)width,(float)height,0.0f,1.0f};
    VkRect2D scissors={ {0,0},{width,height} };
    VkPipelineViewportStateCreateInfo vp={.sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO,
        .viewportCount=1,.pViewports=&viewport,.scissorCount=1,.pScissors=&scissors};
    VkPipelineRasterizationStateCreateInfo rast={.sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO,
        .polygonMode=VK_POLYGON_MODE_FILL,.cullMode=VK_CULL_MODE_NONE,
        .frontFace=VK_FRONT_FACE_COUNTER_CLOCKWISE,.lineWidth=1.0f};
    VkPipelineMultisampleStateCreateInfo ms={.sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO,
        .rasterizationSamples=VK_SAMPLE_COUNT_1_BIT};
    VkPipelineColorBlendAttachmentState blend={.colorWriteMask=VK_COLOR_COMPONENT_R_BIT|
        VK_COLOR_COMPONENT_G_BIT|VK_COLOR_COMPONENT_B_BIT|VK_COLOR_COMPONENT_A_BIT};
    VkPipelineColorBlendStateCreateInfo blends={.sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO,
        .attachmentCount=1,.pAttachments=&blend};
    VkPipelineLayoutCreateInfo gpli={.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    CHECK(vkCreatePipelineLayout(device,&gpli,NULL,&gfxLayout),"vkCreatePipelineLayout(graphics)");
    VkGraphicsPipelineCreateInfo gpci={.sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO,
        .stageCount=2,.pStages=stages,.pVertexInputState=&vertex,
        .pInputAssemblyState=&assembly,.pViewportState=&vp,
        .pRasterizationState=&rast,.pMultisampleState=&ms,
        .pColorBlendState=&blends,.layout=gfxLayout,.renderPass=renderPass,.subpass=0};
    CHECK(vkCreateGraphicsPipelines(device,VK_NULL_HANDLE,1,&gpci,NULL,&gfxPipeline),"vkCreateGraphicsPipelines");

    VkCommandPoolCreateInfo pci={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .queueFamilyIndex=graphicFamily,.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT};
    CHECK(vkCreateCommandPool(device,&pci,NULL,&pool),"vkCreateCommandPool");
    VkCommandBufferAllocateInfo alloc={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool=pool,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=1};
    CHECK(vkAllocateCommandBuffers(device,&alloc,&cmd),"vkAllocateCommandBuffers");
    VkSemaphoreCreateInfo sem={.sType=VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
    CHECK(vkCreateSemaphore(device,&sem,NULL,&ready),"vkCreateSemaphore(acquire)");
    CHECK(vkCreateSemaphore(device,&sem,NULL,&drawn),"vkCreateSemaphore(present)");
    VkFenceCreateInfo fi={.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
        .flags=VK_FENCE_CREATE_SIGNALED_BIT};
    CHECK(vkCreateFence(device,&fi,NULL,&fence),"vkCreateFence");
    if(timestamps) {
        VkQueryPoolCreateInfo qpi={.sType=VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO,
            .queryType=VK_QUERY_TYPE_TIMESTAMP,.queryCount=2};
        if(vkCreateQueryPool(device,&qpi,NULL,&queryPool)!=VK_SUCCESS) timestamps=false;
    }
    // Stage 3: one independent compute dispatch on a host coherent storage buffer.
    if(doCompute){
        VkBufferCreateInfo bci={.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
            .size=256*sizeof(uint32_t),.usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
            .sharingMode=VK_SHARING_MODE_EXCLUSIVE};
        CHECK(vkCreateBuffer(device,&bci,NULL,&computeBuffer),"vkCreateBuffer(compute)");
        VkMemoryRequirements mr;
        vkGetBufferMemoryRequirements(device,computeBuffer,&mr);
        uint32_t idx=choose_memory(physical,mr.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if(idx!=UINT32_MAX){
            VkMemoryAllocateInfo mi={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                .allocationSize=mr.size,.memoryTypeIndex=idx};
            CHECK(vkAllocateMemory(device,&mi,NULL,&computeMemory),"vkAllocateMemory(compute)");
            CHECK(vkBindBufferMemory(device,computeBuffer,computeMemory,0),"vkBindBufferMemory(compute)");
            VkDescriptorSetLayoutBinding binding={.binding=0,.descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
                .descriptorCount=1,.stageFlags=VK_SHADER_STAGE_COMPUTE_BIT};
            VkDescriptorSetLayoutCreateInfo slci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
                .bindingCount=1,.pBindings=&binding};
            CHECK(vkCreateDescriptorSetLayout(device,&slci,NULL,&setLayout),"vkCreateDescriptorSetLayout");
            VkPipelineLayoutCreateInfo clci={.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
                .setLayoutCount=1,.pSetLayouts=&setLayout};
            CHECK(vkCreatePipelineLayout(device,&clci,NULL,&compLayout),"vkCreatePipelineLayout(compute)");
            VkDescriptorPoolSize poolsize={.type=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.descriptorCount=1};
            VkDescriptorPoolCreateInfo dpci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
                .poolSizeCount=1,.pPoolSizes=&poolsize,.maxSets=1};
            CHECK(vkCreateDescriptorPool(device,&dpci,NULL,&setPool),"vkCreateDescriptorPool");
            VkDescriptorSetAllocateInfo dsai={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
                .descriptorPool=setPool,.descriptorSetCount=1,.pSetLayouts=&setLayout};
            CHECK(vkAllocateDescriptorSets(device,&dsai,&descriptor),"vkAllocateDescriptorSets");
            VkDescriptorBufferInfo dbi={.buffer=computeBuffer,.offset=0,.range=256*sizeof(uint32_t)};
            VkWriteDescriptorSet write={.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
                .dstSet=descriptor,.dstBinding=0,.descriptorCount=1,
                .descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.pBufferInfo=&dbi};
            vkUpdateDescriptorSets(device,1,&write,0,NULL);
            VkShaderModuleCreateInfo cci={.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
                .codeSize=sizeof(rm11_comp_spv),.pCode=rm11_comp_spv};
            CHECK(vkCreateShaderModule(device,&cci,NULL,&comp),"vkCreateShaderModule(compute)");
            VkComputePipelineCreateInfo cpci={.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
                .stage={.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
                    .stage=VK_SHADER_STAGE_COMPUTE_BIT,.module=comp,.pName="main"},.layout=compLayout};
            CHECK(vkCreateComputePipelines(device,VK_NULL_HANDLE,1,&cpci,NULL,&compPipeline),"vkCreateComputePipelines");
            void *mem=NULL;
            CHECK(vkMapMemory(device,computeMemory,0,256*sizeof(uint32_t),0,&mem),"vkMapMemory(init)");
            memset(mem,0,256*sizeof(uint32_t));
            vkUnmapMemory(device,computeMemory);
            VkCommandBufferBeginInfo begin={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
            CHECK(vkBeginCommandBuffer(cmd,&begin),"vkBeginCommandBuffer(compute)");
            vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,compPipeline);
            vkCmdBindDescriptorSets(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,compLayout,0,1,&descriptor,0,NULL);
            vkCmdDispatch(cmd,4,1,1);
            CHECK(vkEndCommandBuffer(cmd),"vkEndCommandBuffer(compute)");
            VkSubmitInfo submit={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,.commandBufferCount=1,
                .pCommandBuffers=&cmd};
            CHECK(vkQueueSubmit(queue,1,&submit,VK_NULL_HANDLE),"vkQueueSubmit(compute)");
            CHECK(vkQueueWaitIdle(queue),"vkQueueWaitIdle(compute)");
            CHECK(vkMapMemory(device,computeMemory,0,256*sizeof(uint32_t),0,&mem),"vkMapMemory(verify)");
            computeMismatches=0;
            uint32_t *readback=(uint32_t*)mem;
            for(uint32_t i=0;i<256;i++)if(readback[i]!=i*3u+7u)computeMismatches++;
            vkUnmapMemory(device,computeMemory);
            compute=(computeMismatches==0);
            CHECK(vkResetCommandBuffer(cmd,0),"vkResetCommandBuffer(after compute)");
        }
    }

    // Stage 2 & 4: render triangle with real vertex/fragment shaders, sync and timestamp queries.
    const uint32_t count=240;
    double started=now_seconds();
    double gpuTotalNs=0.0;
    uint32_t measuredQueries=0;
    for(uint32_t i=0;i<count;i++) {
        CHECK(vkWaitForFences(device,1,&fence,VK_TRUE,UINT64_MAX),"vkWaitForFences");
        uint32_t imageIndex=0;
        rc=vkAcquireNextImageKHR(device,swapchain,UINT64_MAX,ready,VK_NULL_HANDLE,&imageIndex);
        if(rc!=VK_SUCCESS && rc!=VK_SUBOPTIMAL_KHR){stage="vkAcquireNextImageKHR";goto done;}
        CHECK(vkResetCommandBuffer(cmd,0),"vkResetCommandBuffer(graphics)");
        VkCommandBufferBeginInfo bi={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        CHECK(vkBeginCommandBuffer(cmd,&bi),"vkBeginCommandBuffer(graphics)");
        if(queryPool){
            vkCmdResetQueryPool(cmd,queryPool,0,2);
            vkCmdWriteTimestamp(cmd,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,queryPool,0);
        }
        VkClearValue clear={.color={{0.04f,0.07f,0.12f,1.0f}}};
        VkRenderPassBeginInfo rbi={.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
            .renderPass=renderPass,.framebuffer=framebuffers[imageIndex],
            .renderArea={{0,0},{width,height}},.clearValueCount=1,.pClearValues=&clear};
        vkCmdBeginRenderPass(cmd,&rbi,VK_SUBPASS_CONTENTS_INLINE);
        vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_GRAPHICS,gfxPipeline);
        vkCmdDraw(cmd,3,1,0,0);
        vkCmdEndRenderPass(cmd);
        if(queryPool)vkCmdWriteTimestamp(cmd,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,queryPool,1);
        CHECK(vkEndCommandBuffer(cmd),"vkEndCommandBuffer(graphics)");
        CHECK(vkResetFences(device,1,&fence),"vkResetFences");
        VkPipelineStageFlags wait=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo si={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
            .waitSemaphoreCount=1,.pWaitSemaphores=&ready,.pWaitDstStageMask=&wait,
            .commandBufferCount=1,.pCommandBuffers=&cmd,
            .signalSemaphoreCount=1,.pSignalSemaphores=&drawn};
        CHECK(vkQueueSubmit(queue,1,&si,fence),"vkQueueSubmit(graphics)");
        VkPresentInfoKHR pi={.sType=VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
            .waitSemaphoreCount=1,.pWaitSemaphores=&drawn,
            .swapchainCount=1,.pSwapchains=&swapchain,.pImageIndices=&imageIndex};
        rc=vkQueuePresentKHR(presentQueue,&pi);
        if(rc!=VK_SUCCESS && rc!=VK_SUBOPTIMAL_KHR){stage="vkQueuePresentKHR";goto done;}
        CHECK(vkQueueWaitIdle(presentQueue),"vkQueueWaitIdle(present)");
        if(queryPool){
            uint64_t ticks[2]={0,0};
            VkResult qrc=vkGetQueryPoolResults(device,queryPool,0,2,sizeof(ticks),ticks,sizeof(uint64_t),
                VK_QUERY_RESULT_64_BIT|VK_QUERY_RESULT_WAIT_BIT);
            if(qrc==VK_SUCCESS && ticks[1]>=ticks[0]){
                gpuTotalNs+=(double)(ticks[1]-ticks[0])*props.limits.timestampPeriod;
                measuredQueries++;
            }
        }
        frames++;
    }
    {
        double duration=now_seconds()-started;
        if(duration>0) {measuredFps=(double)frames/duration;wallFrameMs=1000.0*duration/(double)frames;}
        if(measuredQueries){ gpuTimeMs=(float)(gpuTotalNs/(1.0e6*(double)measuredQueries));timestampValid=true; }
    }
    triangle=(frames==count);
    stage="completed Vulkan shader/compute/presentation suite";
    rc=VK_SUCCESS;

done:
    if(device)vkDeviceWaitIdle(device);
    if(queryPool)vkDestroyQueryPool(device,queryPool,NULL);
    if(setPool)vkDestroyDescriptorPool(device,setPool,NULL);
    if(compPipeline)vkDestroyPipeline(device,compPipeline,NULL);
    if(gfxPipeline)vkDestroyPipeline(device,gfxPipeline,NULL);
    if(compLayout)vkDestroyPipelineLayout(device,compLayout,NULL);
    if(gfxLayout)vkDestroyPipelineLayout(device,gfxLayout,NULL);
    if(setLayout)vkDestroyDescriptorSetLayout(device,setLayout,NULL);
    if(vert)vkDestroyShaderModule(device,vert,NULL);
    if(frag)vkDestroyShaderModule(device,frag,NULL);
    if(comp)vkDestroyShaderModule(device,comp,NULL);
    if(computeBuffer)vkDestroyBuffer(device,computeBuffer,NULL);
    if(computeMemory)vkFreeMemory(device,computeMemory,NULL);
    if(fence)vkDestroyFence(device,fence,NULL);
    if(ready)vkDestroySemaphore(device,ready,NULL);
    if(drawn)vkDestroySemaphore(device,drawn,NULL);
    if(pool)vkDestroyCommandPool(device,pool,NULL);
    if(framebuffers)for(uint32_t i=0;i<imageCount;i++)if(framebuffers[i])vkDestroyFramebuffer(device,framebuffers[i],NULL);
    if(renderPass)vkDestroyRenderPass(device,renderPass,NULL);
    if(views)for(uint32_t i=0;i<imageCount;i++)if(views[i])vkDestroyImageView(device,views[i],NULL);
    if(swapchain)vkDestroySwapchainKHR(device,swapchain,NULL);
    free(framebuffers);free(views);free(images);
    if(device)vkDestroyDevice(device,NULL);
    if(surface)vkDestroySurfaceKHR(instance,surface,NULL);
    if(instance)vkDestroyInstance(instance,NULL);
    if(window)ANativeWindow_release(window);
    snprintf(result,sizeof(result),
       "{\"vkResult\":%d,\"stage\":\"%s\",\"gpu\":\"%s\",\"apiMajor\":%u,\"apiMinor\":%u,"
       "\"width\":%u,\"height\":%u,\"shaderModules\":%s,\"trianglePresented\":%s,"
       "\"computeVerified\":%s,\"computeMismatches\":%d,\"computeAvailable\":%s,"
       "\"timestampAvailable\":%s,\"timestampMeasured\":%s,\"gpuAvgMs\":%.3f,"
       "\"frames\":%u,\"fps\":%.2f,\"frameMs\":%.3f,"
       "\"descriptorIndexingAdvertised\":%s,\"timelineAdvertised\":%s,\"memoryBudgetAdvertised\":%s}",
       (int)rc,stage,gpu,VK_API_VERSION_MAJOR(props.apiVersion),VK_API_VERSION_MINOR(props.apiVersion),
       width,height,shaders?"true":"false",triangle?"true":"false",
       compute?"true":"false",computeMismatches,doCompute?"true":"false",
       timestamps?"true":"false",timestampValid?"true":"false",gpuTimeMs,
       frames,measuredFps,wallFrameMs,
       extDescriptor?"true":"false",extTimeline?"true":"false",extMemoryBudget?"true":"false");
    return (*env)->NewStringUTF(env,result);
#undef CHECK
}
