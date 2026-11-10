
struct M22MeshGroup {uint32_t first,count;};
struct M22Mesh {
    uint32_t vertexCount=0,indexCount=0;
    size_t vertexOffset=0,indexOffset=0;
    std::vector<M22MeshGroup> groups;
};
M22Mesh parseMesh(const std::vector<uint8_t>& b){
    require(b.size()>=48&&b.size()<32u*1024u*1024u,"Invalid FHMS file size");
    require(magic(b,0,"FHMS"),"FHMS header not found");
    require(u32(b,4)==1,"Unsupported FHMS version");
    M22Mesh m;
    m.vertexCount=u32(b,8);m.indexCount=u32(b,12);
    uint32_t groupCount=u32(b,16),stride=u32(b,20);
    require(m.vertexCount>0 && m.vertexCount<150000u &&
        m.indexCount>=3 && m.indexCount<450000u && m.indexCount%3==0 &&
        groupCount>0 && groupCount<128 && stride==32, "Invalid FHMS counts/stride");
    size_t groupBytes=size_t(groupCount)*72u;
    m.vertexOffset=48+groupBytes;
    m.indexOffset=m.vertexOffset+size_t(m.vertexCount)*stride;
    require(m.indexOffset<=b.size() && b.size()-m.indexOffset==size_t(m.indexCount)*4,
        "FHMS binary sections mismatch");
    uint32_t expectedFirst=0;
    for(uint32_t i=0;i<groupCount;++i) {
        uint32_t first=u32(b,48+size_t(i)*72+64);
        uint32_t count=u32(b,48+size_t(i)*72+68);
        require(count>0 && count%3==0 && first==expectedFirst &&
            first<=m.indexCount && count<=m.indexCount-first,"Invalid FHMS submesh range");
        m.groups.push_back({first,count});
        expectedFirst+=count;
    }
    require(expectedFirst==m.indexCount,"Missing or overlapping submesh range");
    for(uint32_t i=0;i<m.indexCount;++i) {
        require(u32(b,m.indexOffset+size_t(i)*4)<m.vertexCount,"FHMS index out of range");
    }
    for(uint32_t i=0;i<m.vertexCount;++i) {
        size_t off=m.vertexOffset+size_t(i)*32;
        for(int j=0;j<8;++j) {
            float f;
            std::memcpy(&f,b.data()+off+j*4,4);
            require(std::isfinite(f) && std::fabs(f)<100000.0f,"Invalid FHMS vertex float");
        }
    }
    return m;
}
struct M22Context {
    VkInstance instance=VK_NULL_HANDLE;
    VkDevice d=VK_NULL_HANDLE;
    VkBuffer meshBuffer=VK_NULL_HANDLE,readBuffer=VK_NULL_HANDLE;
    VkDeviceMemory meshMemory=VK_NULL_HANDLE,readMemory=VK_NULL_HANDLE;
    VkImage colorImage=VK_NULL_HANDLE,depthImage=VK_NULL_HANDLE;
    VkDeviceMemory colorMemory=VK_NULL_HANDLE,depthMemory=VK_NULL_HANDLE;
    VkImageView colorView=VK_NULL_HANDLE,depthView=VK_NULL_HANDLE;
    VkRenderPass pass=VK_NULL_HANDLE;
    VkFramebuffer framebuffer=VK_NULL_HANDLE;
    VkPipelineLayout layout=VK_NULL_HANDLE;
    VkPipeline pipeline=VK_NULL_HANDLE;
    VkShaderModule vert=VK_NULL_HANDLE,frag=VK_NULL_HANDLE;
    VkCommandPool commandPool=VK_NULL_HANDLE;
    ~M22Context() {
        if(d){
            if(commandPool)vkDestroyCommandPool(d,commandPool,nullptr);
            if(pipeline)vkDestroyPipeline(d,pipeline,nullptr);
            if(layout)vkDestroyPipelineLayout(d,layout,nullptr);
            if(vert)vkDestroyShaderModule(d,vert,nullptr);
            if(frag)vkDestroyShaderModule(d,frag,nullptr);
            if(framebuffer)vkDestroyFramebuffer(d,framebuffer,nullptr);
            if(pass)vkDestroyRenderPass(d,pass,nullptr);
            if(colorView)vkDestroyImageView(d,colorView,nullptr);
            if(depthView)vkDestroyImageView(d,depthView,nullptr);
            if(colorImage)vkDestroyImage(d,colorImage,nullptr);
            if(depthImage)vkDestroyImage(d,depthImage,nullptr);
            if(colorMemory)vkFreeMemory(d,colorMemory,nullptr);
            if(depthMemory)vkFreeMemory(d,depthMemory,nullptr);
            if(meshBuffer)vkDestroyBuffer(d,meshBuffer,nullptr);
            if(readBuffer)vkDestroyBuffer(d,readBuffer,nullptr);
            if(meshMemory)vkFreeMemory(d,meshMemory,nullptr);
            if(readMemory)vkFreeMemory(d,readMemory,nullptr);
            vkDestroyDevice(d,nullptr);
        }
        if(instance)vkDestroyInstance(instance,nullptr);
    }
};
void m22CreateImage(M22Context& ctx,VkPhysicalDevice gpu,VkFormat format,
                    VkImageUsageFlags usage,VkImageAspectFlags aspect,
                    VkImage& image,VkDeviceMemory& mem,VkImageView& view,
                    uint32_t width,uint32_t height){
    VkImageCreateInfo create{};
    create.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    create.imageType=VK_IMAGE_TYPE_2D;
    create.extent={width,height,1};
    create.mipLevels=1;create.arrayLayers=1;
    create.format=format;create.tiling=VK_IMAGE_TILING_OPTIMAL;
    create.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    create.usage=usage;create.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    create.samples=VK_SAMPLE_COUNT_1_BIT;
    vkcheck(vkCreateImage(ctx.d,&create,nullptr,&image),"M22 create image");
    VkMemoryRequirements mr{};
    vkGetImageMemoryRequirements(ctx.d,image,&mr);
    VkMemoryAllocateInfo allocation{};
    allocation.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocation.allocationSize=mr.size;
    allocation.memoryTypeIndex=chooseMemory(gpu,mr.memoryTypeBits,VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    vkcheck(vkAllocateMemory(ctx.d,&allocation,nullptr,&mem),"M22 allocate image");
    vkcheck(vkBindImageMemory(ctx.d,image,mem,0),"M22 bind image");
    VkImageViewCreateInfo ci{};
    ci.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    ci.image=image;ci.viewType=VK_IMAGE_VIEW_TYPE_2D;
    ci.format=format;ci.subresourceRange.aspectMask=aspect;
    ci.subresourceRange.levelCount=1;ci.subresourceRange.layerCount=1;
    vkcheck(vkCreateImageView(ctx.d,&ci,nullptr,&view),"M22 image view");
}
void m22CreateBuffer(M22Context& ctx,VkPhysicalDevice gpu,VkDeviceSize size,
                     VkBufferUsageFlags usage,VkBuffer& buffer,VkDeviceMemory& mem){
    VkBufferCreateInfo ci{};
    ci.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    ci.size=size;ci.usage=usage;ci.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    vkcheck(vkCreateBuffer(ctx.d,&ci,nullptr,&buffer),"M22 create buffer");
    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(ctx.d,buffer,&mr);
    VkMemoryAllocateInfo ai{};
    ai.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize=mr.size;
    ai.memoryTypeIndex=chooseMemory(gpu,mr.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    vkcheck(vkAllocateMemory(ctx.d,&ai,nullptr,&mem),"M22 allocate buffer memory");
    vkcheck(vkBindBufferMemory(ctx.d,buffer,mem,0),"M22 bind buffer");
}
std::vector<uint32_t> renderMeshM22(const std::vector<uint8_t>& binary,float angle,float elevation,float zoom) {
    M22Mesh mesh=parseMesh(binary);
    require(std::isfinite(angle) && std::isfinite(elevation) && std::isfinite(zoom),"Invalid camera params");
    require(elevation>=0.10f&&elevation<=1.22f&&zoom>=0.70f&&zoom<=1.45f,"Camera outside valid bounds");
    M22Context ctx;
    VkApplicationInfo ai{};ai.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
    ai.pApplicationName="FH5 M22 3D renderer";ai.apiVersion=VK_API_VERSION_1_0;
    VkInstanceCreateInfo instance{};
    instance.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;instance.pApplicationInfo=&ai;
    vkcheck(vkCreateInstance(&instance,nullptr,&ctx.instance),"M22 create instance");
    uint32_t gpuCount=0;
    vkcheck(vkEnumeratePhysicalDevices(ctx.instance,&gpuCount,nullptr),"M22 enumerate gpu");
    require(gpuCount>0,"Vulkan GPU missing");
    std::vector<VkPhysicalDevice> gpuList(gpuCount);
    vkcheck(vkEnumeratePhysicalDevices(ctx.instance,&gpuCount,gpuList.data()),"M22 gpu list");
    VkPhysicalDevice gpu=gpuList[0];
    uint32_t familyCount=0;
    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,nullptr);
    require(familyCount>0,"GPU queue families missing");
    std::vector<VkQueueFamilyProperties> families(familyCount);
    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&familyCount,families.data());
    uint32_t family=UINT32_MAX;
    for(uint32_t i=0;i<familyCount;++i)
        if(families[i].queueCount && (families[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)) {
            family=i;break;
        }
    require(family!=UINT32_MAX,"GPU has no graphics queue");
    VkFormatProperties colorProperties{},depthProperties{};
    vkGetPhysicalDeviceFormatProperties(gpu,VK_FORMAT_R8G8B8A8_UNORM,&colorProperties);
    vkGetPhysicalDeviceFormatProperties(gpu,VK_FORMAT_D16_UNORM,&depthProperties);
    require((colorProperties.optimalTilingFeatures&VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT)!=0,
        "GPU no RGBA8 render target");
    require((depthProperties.optimalTilingFeatures&VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT)!=0,
        "GPU no D16 depth support");
    float priority=1;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex=family;queueInfo.queueCount=1;queueInfo.pQueuePriorities=&priority;
    VkDeviceCreateInfo deviceInfo{};
    deviceInfo.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.queueCreateInfoCount=1;deviceInfo.pQueueCreateInfos=&queueInfo;
    vkcheck(vkCreateDevice(gpu,&deviceInfo,nullptr,&ctx.d),"M22 create Vulkan device");
    VkQueue queue=VK_NULL_HANDLE;
    vkGetDeviceQueue(ctx.d,family,0,&queue);
    const uint32_t W=800,H=800;
    m22CreateImage(ctx,gpu,VK_FORMAT_R8G8B8A8_UNORM,
        VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT|VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
        VK_IMAGE_ASPECT_COLOR_BIT,ctx.colorImage,ctx.colorMemory,ctx.colorView,W,H);
    m22CreateImage(ctx,gpu,VK_FORMAT_D16_UNORM,
        VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT,
        VK_IMAGE_ASPECT_DEPTH_BIT,ctx.depthImage,ctx.depthMemory,ctx.depthView,W,H);
    const VkDeviceSize vertexBytes=VkDeviceSize(mesh.vertexCount)*32u;
    const VkDeviceSize indexBytes=VkDeviceSize(mesh.indexCount)*4u;
    m22CreateBuffer(ctx,gpu,vertexBytes+indexBytes,
        VK_BUFFER_USAGE_VERTEX_BUFFER_BIT|VK_BUFFER_USAGE_INDEX_BUFFER_BIT,
        ctx.meshBuffer,ctx.meshMemory);
    void* mapped=nullptr;
    vkcheck(vkMapMemory(ctx.d,ctx.meshMemory,0,vertexBytes+indexBytes,0,&mapped),"M22 map mesh");
    std::memcpy(mapped,binary.data()+mesh.vertexOffset,size_t(vertexBytes));
    std::memcpy(static_cast<uint8_t*>(mapped)+vertexBytes,
        binary.data()+mesh.indexOffset,size_t(indexBytes));
    vkUnmapMemory(ctx.d,ctx.meshMemory);

    VkAttachmentDescription attachments[2]{};
    attachments[0].format=VK_FORMAT_R8G8B8A8_UNORM;
    attachments[0].samples=VK_SAMPLE_COUNT_1_BIT;
    attachments[0].loadOp=VK_ATTACHMENT_LOAD_OP_CLEAR;
    attachments[0].storeOp=VK_ATTACHMENT_STORE_OP_STORE;
    attachments[0].initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    attachments[0].finalLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    attachments[1].format=VK_FORMAT_D16_UNORM;
    attachments[1].samples=VK_SAMPLE_COUNT_1_BIT;
    attachments[1].loadOp=VK_ATTACHMENT_LOAD_OP_CLEAR;
    attachments[1].storeOp=VK_ATTACHMENT_STORE_OP_DONT_CARE;
    attachments[1].initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    attachments[1].finalLayout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    VkAttachmentReference refs[2]{};
    refs[0].attachment=0;refs[0].layout=VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    refs[1].attachment=1;refs[1].layout=VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint=VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount=1;subpass.pColorAttachments=&refs[0];
    subpass.pDepthStencilAttachment=&refs[1];
    VkSubpassDependency deps[2]{};
    deps[0].srcSubpass=VK_SUBPASS_EXTERNAL;deps[0].dstSubpass=0;
    deps[0].srcStageMask=VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT;
    deps[0].dstStageMask=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT|
        VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    deps[0].dstAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT|
        VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    deps[1].srcSubpass=0;deps[1].dstSubpass=VK_SUBPASS_EXTERNAL;
    deps[1].srcStageMask=VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[1].dstStageMask=VK_PIPELINE_STAGE_TRANSFER_BIT;
    deps[1].srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[1].dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
    VkRenderPassCreateInfo pass{};
    pass.sType=VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    pass.attachmentCount=2;pass.pAttachments=attachments;
    pass.subpassCount=1;pass.pSubpasses=&subpass;
    pass.dependencyCount=2;pass.pDependencies=deps;
    vkcheck(vkCreateRenderPass(ctx.d,&pass,nullptr,&ctx.pass),"M22 render pass");
    VkImageView views[]={ctx.colorView,ctx.depthView};
    VkFramebufferCreateInfo fbi{};
    fbi.sType=VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
    fbi.renderPass=ctx.pass;fbi.attachmentCount=2;fbi.pAttachments=views;
    fbi.width=W;fbi.height=H;fbi.layers=1;
    vkcheck(vkCreateFramebuffer(ctx.d,&fbi,nullptr,&ctx.framebuffer),"M22 framebuffer");

    VkShaderModuleCreateInfo sm{};
    sm.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.pCode=fh5_mesh_vert_spv;sm.codeSize=sizeof(fh5_mesh_vert_spv);
    vkcheck(vkCreateShaderModule(ctx.d,&sm,nullptr,&ctx.vert),"M22 vertex shader");
    sm.pCode=fh5_mesh_frag_spv;sm.codeSize=sizeof(fh5_mesh_frag_spv);
    vkcheck(vkCreateShaderModule(ctx.d,&sm,nullptr,&ctx.frag),"M22 fragment shader");
    VkPushConstantRange push{};
    push.offset=0;push.size=sizeof(float)*8;push.stageFlags=VK_SHADER_STAGE_VERTEX_BIT;
    VkPipelineLayoutCreateInfo pipelineLayout{};
    pipelineLayout.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayout.pushConstantRangeCount=1;pipelineLayout.pPushConstantRanges=&push;
    vkcheck(vkCreatePipelineLayout(ctx.d,&pipelineLayout,nullptr,&ctx.layout),"M22 pipeline layout");
    VkPipelineShaderStageCreateInfo stages[2]{};
    for(uint32_t i=0;i<2;++i){
        stages[i].sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stages[i].stage=i==0?VK_SHADER_STAGE_VERTEX_BIT:VK_SHADER_STAGE_FRAGMENT_BIT;
        stages[i].module=i==0?ctx.vert:ctx.frag;stages[i].pName="main";
    }
    VkVertexInputBindingDescription bind{};
    bind.binding=0;bind.stride=32;bind.inputRate=VK_VERTEX_INPUT_RATE_VERTEX;
    VkVertexInputAttributeDescription attributes[3]{};
    attributes[0]={0,0,VK_FORMAT_R32G32B32_SFLOAT,0};
    attributes[1]={1,0,VK_FORMAT_R32G32B32_SFLOAT,12};
    attributes[2]={2,0,VK_FORMAT_R32G32_SFLOAT,24};
    VkPipelineVertexInputStateCreateInfo vertices{};
    vertices.sType=VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    vertices.vertexBindingDescriptionCount=1;vertices.pVertexBindingDescriptions=&bind;
    vertices.vertexAttributeDescriptionCount=3;vertices.pVertexAttributeDescriptions=attributes;
    VkPipelineInputAssemblyStateCreateInfo topology{};
    topology.sType=VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    topology.topology=VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkViewport viewport{};
    viewport.width=float(W);viewport.height=float(H);viewport.maxDepth=1;
    VkRect2D scissor{};scissor.extent={W,H};
    VkPipelineViewportStateCreateInfo vp{};
    vp.sType=VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp.viewportCount=1;vp.pViewports=&viewport;vp.scissorCount=1;vp.pScissors=&scissor;
    VkPipelineRasterizationStateCreateInfo raster{};
    raster.sType=VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    raster.polygonMode=VK_POLYGON_MODE_FILL;
    raster.cullMode=VK_CULL_MODE_NONE;raster.lineWidth=1;
    VkPipelineMultisampleStateCreateInfo multisample{};
    multisample.sType=VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    multisample.rasterizationSamples=VK_SAMPLE_COUNT_1_BIT;
    VkPipelineDepthStencilStateCreateInfo depth{};
    depth.sType=VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
    depth.depthTestEnable=VK_TRUE;depth.depthWriteEnable=VK_TRUE;
    depth.depthCompareOp=VK_COMPARE_OP_LESS_OR_EQUAL;
    VkPipelineColorBlendAttachmentState blendAttachment{};
    blendAttachment.colorWriteMask=VK_COLOR_COMPONENT_R_BIT|VK_COLOR_COMPONENT_G_BIT|
        VK_COLOR_COMPONENT_B_BIT|VK_COLOR_COMPONENT_A_BIT;
    VkPipelineColorBlendStateCreateInfo blend{};
    blend.sType=VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    blend.attachmentCount=1;blend.pAttachments=&blendAttachment;
    VkGraphicsPipelineCreateInfo pipeline{};
    pipeline.sType=VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    pipeline.stageCount=2;pipeline.pStages=stages;
    pipeline.pVertexInputState=&vertices;
    pipeline.pInputAssemblyState=&topology;
    pipeline.pViewportState=&vp;pipeline.pRasterizationState=&raster;
    pipeline.pMultisampleState=&multisample;
    pipeline.pDepthStencilState=&depth;
    pipeline.pColorBlendState=&blend;
    pipeline.layout=ctx.layout;pipeline.renderPass=ctx.pass;
    vkcheck(vkCreateGraphicsPipelines(ctx.d,VK_NULL_HANDLE,1,&pipeline,nullptr,&ctx.pipeline),
        "M22 graphics pipeline");

    const size_t bytes=size_t(W)*H*4;
    m22CreateBuffer(ctx,gpu,bytes,VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                    ctx.readBuffer,ctx.readMemory);
    VkCommandPoolCreateInfo pci{};
    pci.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;pci.queueFamilyIndex=family;
    vkcheck(vkCreateCommandPool(ctx.d,&pci,nullptr,&ctx.commandPool),"M22 command pool");
    VkCommandBufferAllocateInfo cmdAlloc{};
    cmdAlloc.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cmdAlloc.commandPool=ctx.commandPool;
    cmdAlloc.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;cmdAlloc.commandBufferCount=1;
    VkCommandBuffer command=VK_NULL_HANDLE;
    vkcheck(vkAllocateCommandBuffers(ctx.d,&cmdAlloc,&command),"M22 command buffer");
    VkCommandBufferBeginInfo cmdBegin{};
    cmdBegin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    cmdBegin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkcheck(vkBeginCommandBuffer(command,&cmdBegin),"M22 begin commands");
    VkClearValue clear[2]{};
    clear[0].color.float32[0]=0.055f;
    clear[0].color.float32[1]=0.075f;
    clear[0].color.float32[2]=0.11f;
    clear[0].color.float32[3]=1.0f;
    clear[1].depthStencil.depth=1;
    VkRenderPassBeginInfo render{};
    render.sType=VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    render.renderPass=ctx.pass;render.framebuffer=ctx.framebuffer;
    render.renderArea.extent={W,H};
    render.clearValueCount=2;render.pClearValues=clear;
    vkCmdBeginRenderPass(command,&render,VK_SUBPASS_CONTENTS_INLINE);
    vkCmdBindPipeline(command,VK_PIPELINE_BIND_POINT_GRAPHICS,ctx.pipeline);
    VkDeviceSize vertexOffset=0;
    vkCmdBindVertexBuffers(command,0,1,&ctx.meshBuffer,&vertexOffset);
    vkCmdBindIndexBuffer(command,ctx.meshBuffer,vertexBytes,VK_INDEX_TYPE_UINT32);
    // Neutral colors reveal depth/shape without pretending the final FH5 carpaint.
    const float palette[][3]={
        {0.73f,0.78f,0.82f},{0.50f,0.68f,0.79f},
        {0.37f,0.62f,0.65f},{0.78f,0.64f,0.45f},
        {0.73f,0.52f,0.52f},{0.62f,0.60f,0.76f}
    };
    for(size_t i=0;i<mesh.groups.size();++i) {
        float color[8]={
            angle,zoom,elevation,0.0f,
            palette[i%6][0],palette[i%6][1],palette[i%6][2],1.0f
        };
        vkCmdPushConstants(command,ctx.layout,VK_SHADER_STAGE_VERTEX_BIT,0,sizeof(color),color);
        vkCmdDrawIndexed(command,mesh.groups[i].count,1,mesh.groups[i].first,0,0);
    }
    vkCmdEndRenderPass(command);
    VkImageMemoryBarrier imageBarrier{};
    imageBarrier.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    imageBarrier.srcAccessMask=VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    imageBarrier.dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT;
    imageBarrier.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    imageBarrier.newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
    imageBarrier.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    imageBarrier.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    imageBarrier.image=ctx.colorImage;
    imageBarrier.subresourceRange.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    imageBarrier.subresourceRange.levelCount=1;
    imageBarrier.subresourceRange.layerCount=1;
    vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,nullptr,0,nullptr,1,&imageBarrier);
    VkBufferImageCopy copy{};
    copy.imageSubresource.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT;
    copy.imageSubresource.layerCount=1;
    copy.imageExtent={W,H,1};
    vkCmdCopyImageToBuffer(command,ctx.colorImage,
        VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,ctx.readBuffer,1,&copy);
    VkBufferMemoryBarrier host{};
    host.sType=VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;
    host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    host.srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    host.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    host.buffer=ctx.readBuffer;
    host.size=VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,
        0,0,nullptr,1,&host,0,nullptr);
    vkcheck(vkEndCommandBuffer(command),"M22 end commands");
    VkSubmitInfo submission{};
    submission.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submission.commandBufferCount=1;submission.pCommandBuffers=&command;
    vkcheck(vkQueueSubmit(queue,1,&submission,VK_NULL_HANDLE),"M22 submit");
    vkcheck(vkQueueWaitIdle(queue),"M22 GPU completion");

    void* outBytes=nullptr;
    vkcheck(vkMapMemory(ctx.d,ctx.readMemory,0,bytes,0,&outBytes),"M22 map pixels");
    const uint8_t* src=static_cast<const uint8_t*>(outBytes);
    std::vector<uint32_t> out;
    out.reserve(2+size_t(W)*H);
    out.push_back(W);out.push_back(H);
    size_t nonClear=0;
    for(size_t i=0;i<bytes;i+=4) {
        // Faint navy clear color is approximately (14,19,28).
        if(std::abs(int(src[i])-14)>4 || std::abs(int(src[i+1])-19)>4 ||
           std::abs(int(src[i+2])-28)>4)++nonClear;
        out.push_back((uint32_t(src[i+3])<<24)|
                      (uint32_t(src[i])<<16)|
                      (uint32_t(src[i+1])<<8)|
                      uint32_t(src[i+2]));
    }
    vkUnmapMemory(ctx.d,ctx.readMemory);
    require(nonClear>150,"M22 shader output empty: no visible triangles");
    return out;
}
