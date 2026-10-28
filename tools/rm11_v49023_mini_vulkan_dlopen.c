/*
 * RM11 test-only Vulkan SONAME loader interception.
 * Never install globally: LD_PRELOAD only for explicit RM11-D3D11 MINI tests.
 * Failed custom-load returns the original dlopen result, not a false success.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void *(*open_type)(const char *,int);
extern void *rm11_vnext_open_vulkan(const char *,const char *,int);
void *dlopen(const char *name,int flags) {
    open_type real=(open_type)dlsym(RTLD_NEXT,"dlopen");
    if(!real)return NULL;
    if(!name || strcmp(name,"libvulkan.so.1"))
        return real(name,flags);
    const char *enabled=getenv("RM11_V49023_MINI_VULKAN_BRIDGE");
    const char *root=getenv("RM11_V49023_SIGNED_NATIVE_LIB_DIR");
    if(!enabled || strcmp(enabled,"1") || !root)
        return real(name,flags);
    fprintf(stderr,"RM11_V49023_WINE_CHILD_VULKAN_SONAME_INTERCEPTED\\n");
    void *custom=rm11_vnext_open_vulkan(name,root,1);
    if(custom) {
        fprintf(stderr,"RM11_V49023_CUSTOM_TURNIP_HANDLE_OPENED_WSI_UNVERIFIED\\n");
        return custom;
    }
    fprintf(stderr,"RM11_V49023_CUSTOM_TURNIP_FAILED_CLOSED_TRY_ORIGINAL\\n");
    return real(name,flags);
}
