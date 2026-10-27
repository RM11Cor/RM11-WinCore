/*
 * RM11 vNext Wine-child Vulkan bridge. Source candidate ONLY.
 * SPDX-License-Identifier: MIT
 *
 * libadrenotools must run in the actual Wine client process (the process
 * which dlopens Wine's native libvulkan.so.1), NOT in the Java activity or
 * in the Wine process supervisor. This is an explicit function, not a global
 * dlopen() interceptor, and there is deliberately NO auto-constructor.
 *
 * The signed/native manifest must be verified by Java before handing control
 * to a prospective caller; this C API can't attest APK signature itself.
 * It is NOT installed in any user's APK and the release gate remains OFF.
 */
#define _GNU_SOURCE
#include "engine_vnext_wine_vulkan_bridge.h"
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef void *(*rm11_adrenotools_open_fn)(int, int, const char *, const char *,
       const char *, const char *, const char *, void **);

static const char *const signed_components[] = {
    "libadrenotools.so",
    "libhook_impl.so",
    "libmain_hook.so",
    "libvulkan_freedreno.so",
    "libc++_shared.so",
};

static int valid_root(const char *root){
    if(!root || root[0]!='/' || root[1]=='\0')return 0;
    size_t n=strnlen(root,PATH_MAX);
    if(n>=PATH_MAX-120 || n<12 || root[n-1]=='/')return 0;
    /* Even when the Java caller supplies a signed nativeLibraryDir, reject
       lexical traversal, doubled slashes and environmental substitutions. */
    if(strstr(root,"/../") || strstr(root,"/./") ||
       strstr(root,"//") || strstr(root,"/..") || strstr(root,"/."))
       return 0;
    return 1;
}

int rm11_vnext_vulkan_policy(const char *soname,const char *native_dir,
                              const char *process_executable,
                              int manifest_verified) {
    if(manifest_verified!=1 || !soname || !native_dir || !process_executable)
        return 0;
    if(strcmp(soname,"libvulkan.so.1") || !valid_root(native_dir))
        return 0;
    char expected[PATH_MAX];
    int n=snprintf(expected,sizeof expected,"%s/libwineprobe.so",native_dir);
    return n>0 && (size_t)n<sizeof expected &&
           !strcmp(process_executable,expected);
}

static int signed_file_in_dir(const char *root,const char *name){
    char path[PATH_MAX];
    int n=snprintf(path,sizeof path,"%s/%s",root,name);
    if(n<=0||(size_t)n>=sizeof path)return 0;
    struct stat st;
    if(lstat(path,&st)<0 || !S_ISREG(st.st_mode) || st.st_size<4096)
        return 0;
    return 1;
}

void *rm11_vnext_open_vulkan(const char *soname,
                             const char *native_dir,
                             int manifest_verified) {
    /* This caller is expected ONLY in the signed native Wine client.
     * Checking /proc/self/exe avoids misrouting the supervisor, wineserver,
     * Java process, other app processes and arbitrary user executables. */
    char actual[PATH_MAX];
    ssize_t n=readlink("/proc/self/exe",actual,sizeof actual-1);
    if(n<=0||(size_t)n>=sizeof actual)return NULL;
    actual[n]='\0';
    if(!rm11_vnext_vulkan_policy(soname,native_dir,actual,manifest_verified))
        return NULL;

    for(size_t i=0;i<sizeof signed_components/sizeof signed_components[0];i++)
        if(!signed_file_in_dir(native_dir,signed_components[i]))
            return NULL;

    char ado_path[PATH_MAX], driver_root[PATH_MAX];
    n=snprintf(ado_path,sizeof ado_path,"%s/libadrenotools.so",native_dir);
    if(n<=0||(size_t)n>=sizeof ado_path)return NULL;
    n=snprintf(driver_root,sizeof driver_root,"%s/",native_dir);
    if(n<=0||(size_t)n>=sizeof driver_root)return NULL;

    /* The old /vendor loader and temporary writable ImageFs are NEVER used.
     * Custom driver is under signed APK nativeLibraryDir, with slash appended
     * exactly as libadrenotools' upstream concatenation expects. */
    void *ado=dlopen(ado_path,RTLD_NOW|RTLD_LOCAL);
    if(!ado)return NULL;
    rm11_adrenotools_open_fn open_custom=
        (rm11_adrenotools_open_fn)dlsym(ado,"adrenotools_open_libvulkan");
    if(!open_custom)return NULL;
    enum {RM11_ADRENOTOOLS_DRIVER_CUSTOM=1};
    return open_custom(RTLD_NOW|RTLD_LOCAL,RM11_ADRENOTOOLS_DRIVER_CUSTOM,
                       NULL,native_dir,driver_root,"libvulkan_freedreno.so",
                       NULL,NULL);
}
