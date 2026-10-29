/*
 * RM11 v4.90.27: mini-test-only Vulkan loader bridge to the APK-pinned Mesa ICD.
 * This is NOT a full Vulkan loader or WSI provider. No Android system linker
 * internals, libadrenotools, vendor driver fallback, or game activation.
 * Export the loader API entry points Wine needs to probe the ICD.
 *
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef PFN_vkVoidFunction (*icd_get_proc_fn)(VkInstance,const char *);
typedef VkResult (*icd_negotiate_fn)(uint32_t *);
typedef void *(*real_dlopen_fn)(const char *,int);

static icd_get_proc_fn icd_get_proc;
static VkInstance last_instance;

static void stage(const char *s) {
    fprintf(stderr,"RM11_V49027_DIRECT_ICD_STAGE=%s\n",s);
}
static real_dlopen_fn real_open(void) {
    real_dlopen_fn result=NULL;
    void *symbol=dlsym(RTLD_NEXT,"dlopen");
    if(sizeof(result)==sizeof(symbol))memcpy(&result,&symbol,sizeof(result));
    return result;
}
static void *open_private_icd(void) {
    icd_get_proc_fn current=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    if(current)return (void *)1; /* initialized earlier; do not retry */
    const char *root=getenv("RM11_V49027_NATIVE_LIB_DIR");
    if(!root || strncmp(root,"/data/app/",10) || strlen(root)>PATH_MAX-40
            || strstr(root,"/../") || strstr(root,"//")) {
        stage("REJECT_UNTRUSTED_NATIVE_PATH");
        return NULL;
    }
    char path[PATH_MAX];
    if(snprintf(path,sizeof path,"%s/libvulkan_freedreno.so",root)>=(int)sizeof path) {
        stage("PATH_TOO_LONG");return NULL;
    }
    struct stat st;
    if(lstat(path,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<4096) {
        stage("TURNIP_FILE_INVALID");return NULL;
    }
    real_dlopen_fn real=real_open();
    if(!real){stage("REAL_DLOPEN_UNAVAILABLE");return NULL;}
    stage("TURNIP_DLOPEN_REQUESTED");
    void *icd=real(path,RTLD_NOW|RTLD_LOCAL);
    if(!icd) {
        const char *error=dlerror();
        fprintf(stderr,"RM11_V49027_DIRECT_ICD_STAGE=TURNIP_DLOPEN_FAILED DETAIL=%.220s\n",
                error?error:"UNKNOWN");
        return NULL;
    }
    stage("TURNIP_DLOPEN_SUCCEEDED");
    void *gpa_symbol=dlsym(icd,"vk_icdGetInstanceProcAddr");
    if(!gpa_symbol || sizeof(gpa_symbol)!=sizeof(icd_get_proc_fn)) {
        stage("ICD_GET_INSTANCE_PROC_MISSING");return NULL;
    }
    icd_get_proc_fn get_proc=NULL;
    memcpy(&get_proc,&gpa_symbol,sizeof(get_proc));
    void *negotiate_symbol=dlsym(icd,"vk_icdNegotiateLoaderICDInterfaceVersion");
    if(negotiate_symbol){
        icd_negotiate_fn negotiate=NULL;
        if(sizeof(negotiate)!=sizeof(negotiate_symbol)) {
            stage("ICD_NEGOTIATE_ABI_MISMATCH");return NULL;
        }
        memcpy(&negotiate,&negotiate_symbol,sizeof(negotiate));
        uint32_t version=7;
        VkResult result=negotiate(&version);
        fprintf(stderr,"RM11_V49027_ICD_NEGOTIATE_RESULT=%d VERSION=%u\n",
                (int)result,(unsigned)version);
        if(result!=VK_SUCCESS || version<1) {
            stage("ICD_NEGOTIATION_FAILED");return NULL;
        }
    }else stage("ICD_NEGOTIATION_V1_COMPAT");
    if(!get_proc(VK_NULL_HANDLE,"vkCreateInstance")
            || !get_proc(VK_NULL_HANDLE,"vkEnumerateInstanceExtensionProperties")) {
        stage("ICD_GLOBAL_API_MISSING");return NULL;
    }
    __atomic_store_n(&icd_get_proc,get_proc,__ATOMIC_RELEASE);
    stage("ICD_GLOBAL_API_READY_WSI_UNVERIFIED");
    return icd;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance,
                                                              const char *name);
VKAPI_ATTR VkResult VKAPI_CALL vkCreateInstance(const VkInstanceCreateInfo *,
                                                const VkAllocationCallbacks *,VkInstance *);
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceExtensionProperties(const char *,
                                                   uint32_t *,VkExtensionProperties *);
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(uint32_t *,
                                                   VkLayerProperties *);
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceVersion(uint32_t *);
VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice,const char *);

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance,
                                                              const char *name) {
    if(!name)return NULL;
    if(!strcmp(name,"vkGetInstanceProcAddr"))return (PFN_vkVoidFunction)&vkGetInstanceProcAddr;
    if(!strcmp(name,"vkGetDeviceProcAddr"))return (PFN_vkVoidFunction)&vkGetDeviceProcAddr;
    if(!strcmp(name,"vkCreateInstance"))return (PFN_vkVoidFunction)&vkCreateInstance;
    if(!strcmp(name,"vkEnumerateInstanceExtensionProperties"))
        return (PFN_vkVoidFunction)&vkEnumerateInstanceExtensionProperties;
    if(!strcmp(name,"vkEnumerateInstanceLayerProperties"))
        return (PFN_vkVoidFunction)&vkEnumerateInstanceLayerProperties;
    if(!strcmp(name,"vkEnumerateInstanceVersion"))
        return (PFN_vkVoidFunction)&vkEnumerateInstanceVersion;
    icd_get_proc_fn gpa=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    return gpa?gpa(instance,name):NULL;
}

VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceExtensionProperties(
                        const char *layer,uint32_t *count,VkExtensionProperties *out) {
    if(layer)return VK_ERROR_LAYER_NOT_PRESENT;
    icd_get_proc_fn gpa=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    if(!gpa)return VK_ERROR_INITIALIZATION_FAILED;
    PFN_vkEnumerateInstanceExtensionProperties fn=NULL;
    PFN_vkVoidFunction symbol=gpa(VK_NULL_HANDLE,"vkEnumerateInstanceExtensionProperties");
    if(sizeof(fn)!=sizeof(symbol))return VK_ERROR_INITIALIZATION_FAILED;
    memcpy(&fn,&symbol,sizeof(fn));
    return fn?fn(NULL,count,out):VK_ERROR_INITIALIZATION_FAILED;
}
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(
                                                    uint32_t *count,VkLayerProperties *out) {
    (void)out;
    if(!count)return VK_ERROR_INITIALIZATION_FAILED;
    *count=0;return VK_SUCCESS;
}
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceVersion(uint32_t *out) {
    if(!out)return VK_ERROR_INITIALIZATION_FAILED;
    icd_get_proc_fn gpa=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    if(!gpa)return VK_ERROR_INITIALIZATION_FAILED;
    PFN_vkEnumerateInstanceVersion fn=NULL;
    PFN_vkVoidFunction symbol=gpa(VK_NULL_HANDLE,"vkEnumerateInstanceVersion");
    if(symbol && sizeof(fn)==sizeof(symbol))memcpy(&fn,&symbol,sizeof(fn));
    if(!fn){*out=VK_API_VERSION_1_0;return VK_SUCCESS;}
    return fn(out);
}
VKAPI_ATTR VkResult VKAPI_CALL vkCreateInstance(
                const VkInstanceCreateInfo *info,const VkAllocationCallbacks *alloc,
                VkInstance *instance) {
    icd_get_proc_fn gpa=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    if(!gpa || !info || !instance)return VK_ERROR_INITIALIZATION_FAILED;
    PFN_vkCreateInstance fn=NULL;
    PFN_vkVoidFunction symbol=gpa(VK_NULL_HANDLE,"vkCreateInstance");
    if(sizeof(fn)!=sizeof(symbol))return VK_ERROR_INITIALIZATION_FAILED;
    memcpy(&fn,&symbol,sizeof(fn));
    if(!fn)return VK_ERROR_INITIALIZATION_FAILED;
    stage("VK_CREATE_INSTANCE_REQUESTED");
    VkResult result=fn(info,alloc,instance);
    fprintf(stderr,"RM11_V49027_VK_CREATE_INSTANCE_RESULT=%d\n",(int)result);
    if(result==VK_SUCCESS && *instance)
        __atomic_store_n(&last_instance,*instance,__ATOMIC_RELEASE);
    return result;
}
VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice device,
                                                             const char *name) {
    icd_get_proc_fn gpa=__atomic_load_n(&icd_get_proc,__ATOMIC_ACQUIRE);
    VkInstance inst=__atomic_load_n(&last_instance,__ATOMIC_ACQUIRE);
    if(!gpa || !inst || !name)return NULL;
    PFN_vkGetDeviceProcAddr fn=NULL;
    PFN_vkVoidFunction symbol=gpa(inst,"vkGetDeviceProcAddr");
    if(sizeof(fn)!=sizeof(symbol))return NULL;
    memcpy(&fn,&symbol,sizeof(fn));
    return fn?fn(device,name):NULL;
}

/* Wine asks dlopen("libvulkan.so.1"); supply this APK-private ICD shim.
 * No global Android libvulkan.so substitution or Linker namespace bypass.
 */
__attribute__((visibility("default")))
void *dlopen(const char *name,int flags) {
    real_dlopen_fn real=real_open();
    if(!real)return NULL;
    const char *enabled=getenv("RM11_V49027_PRIVATE_ICD_ENABLED");
    if(!enabled || strcmp(enabled,"1") || !name || strcmp(name,"libvulkan.so.1"))
        return real(name,flags);
    stage("WINE_CHILD_VULKAN_SONAME_INTERCEPTED");
    if(!open_private_icd()) {
        stage("PRIVATE_ICD_SETUP_FAILED_NO_VENDOR_FALLBACK");
        return NULL;
    }
    const char *self=getenv("RM11_V49027_PRIVATE_LOADER_LIBRARY");
    if(!self || strncmp(self,"/data/app/",10)) {
        stage("PRIVATE_LOADER_SELF_PATH_INVALID");return NULL;
    }
    void *handle=real(self,RTLD_NOW|RTLD_LOCAL);
    stage(handle?"PRIVATE_LOADER_HANDLE_RETURNED":"PRIVATE_LOADER_SELF_DLOPEN_FAILED");
    return handle;
}
