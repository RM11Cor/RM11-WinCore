/*
 * RM11 v4.90.28 mini D3D11 only: return the source-verified app-private
 * Termux Bionic desktop Vulkan loader which supports X11 WSI.
 * Does NOT route to the Android Vulkan HAL, AdrenoTools or system libraries.
 * SPDX-License-Identifier: MIT
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
typedef void *(*dlopen_native_fn)(const char *,int);
typedef int32_t (*enumerate_extension_fn)(const char *,uint32_t *,void *);

typedef struct {
    char name[256];
    uint32_t specVersion;
} extension_property;

static dlopen_native_fn native_open(void){
    dlopen_native_fn fn=NULL;
    void *address=dlsym(RTLD_NEXT,"dlopen");
    if(sizeof(fn)==sizeof(address))memcpy(&fn,&address,sizeof(fn));
    return fn;
}
static void trace(const char *label){
    fprintf(stderr,"RM11_V49028_X11_LOADER_STAGE=%s\n",label);
}
static int valid_native(const char *root,const char *name,char out[PATH_MAX]){
    if(!root || strncmp(root,"/data/app/",10) || strlen(root)>PATH_MAX-90
       || strstr(root,"/../") || strstr(root,"/./") || strstr(root,"//"))
        return 0;
    int n=snprintf(out,PATH_MAX,"%s/%s",root,name);
    if(n<0 || n>=PATH_MAX)return 0;
    struct stat st;
    return !lstat(out,&st) && S_ISREG(st.st_mode) && st.st_size>=4096;
}
__attribute__((visibility("default")))
void *dlopen(const char *soname,int flags){
    dlopen_native_fn real=native_open();
    if(!real)return NULL;
    const char *enable=getenv("RM11_V49028_MINI_X11_WSI");
    if(!enable || strcmp(enable,"1") || !soname || strcmp(soname,"libvulkan.so.1"))
        return real(soname,flags);
    trace("WINE_CHILD_SONAME_INTERCEPTED");
    char path[PATH_MAX];
    if(!valid_native(getenv("RM11_V49028_NATIVE_LIB_DIR"),
                     "librm11_vkloader_v473.so",path)){
        trace("SIGNED_DESKTOP_VULKAN_LOADER_NOT_PRESENT");
        return NULL;
    }
    void *vulkan=real(path,RTLD_NOW|RTLD_LOCAL);
    if(!vulkan){
        const char *error=dlerror();
        fprintf(stderr,"RM11_V49028_X11_LOADER_STAGE=PRIVATE_LOADER_DLOPEN_FAILED DETAIL=%.220s\n",
                error?error:"UNKNOWN");
        return NULL;
    }
    trace("PRIVATE_LOADER_DLOPEN_SUCCEEDED");
    if(!dlsym(vulkan,"vkGetInstanceProcAddr")){
        trace("PRIVATE_VULKAN_ENTRY_MISSING");
        return NULL;
    }
    void *symbol=dlsym(vulkan,"vkEnumerateInstanceExtensionProperties");
    enumerate_extension_fn enumerate=NULL;
    if(sizeof(enumerate)!=sizeof(symbol) || !symbol){
        trace("INSTANCE_EXTENSION_ENUMERATOR_MISSING");
        return NULL;
    }
    memcpy(&enumerate,&symbol,sizeof(enumerate));
    uint32_t count=0;
    int32_t rc=enumerate(NULL,&count,NULL);
    if(rc!=0 || !count || count>256){
        fprintf(stderr,"RM11_V49028_X11_LOADER_STAGE=INSTANCE_EXTENSION_QUERY_FAILED RESULT=%d COUNT=%u\n",rc,count);
        return NULL;
    }
    extension_property props[256];
    memset(props,0,sizeof(props));
    rc=enumerate(NULL,&count,props);
    if(rc!=0 || count>256){
        trace("INSTANCE_EXTENSION_LIST_FAILED");
        return NULL;
    }
    int surface=0,xlib=0,xcb=0;
    for(uint32_t i=0;i<count;i++){
        if(!strcmp(props[i].name,"VK_KHR_surface"))surface=1;
        if(!strcmp(props[i].name,"VK_KHR_xlib_surface"))xlib=1;
        if(!strcmp(props[i].name,"VK_KHR_xcb_surface"))xcb=1;
    }
    fprintf(stderr,"RM11_V49028_X11_LOADER_EXTENSIONS=KHR_SURFACE:%d XLIB:%d XCB:%d\n",
            surface,xlib,xcb);
    if(!surface || !(xlib || xcb)){
        trace("REQUIRED_X11_WSI_EXTENSIONS_MISSING");
        return NULL;
    }
    trace("X11_WSI_LOADER_READY_GPU_UNVERIFIED");
    return vulkan;
}
