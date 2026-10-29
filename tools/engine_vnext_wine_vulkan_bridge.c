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
#include <stdlib.h>
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

static void v49024_probe(const char *stage,const char *component) {
    const char *enabled=getenv("RM11_V49024_MINI_LOADER_DIAGNOSTICS");
    if(!enabled || strcmp(enabled,"1"))return;
    fprintf(stderr,"RM11_V49024_TURNIP_LOADER_STAGE=%s",stage);
    if(component)fprintf(stderr," COMPONENT=%s",component);
    fputc(10,stderr);
}

void *rm11_vnext_open_vulkan(const char *soname,
                             const char *native_dir,
                             int manifest_verified) {
    /* This caller is expected ONLY in the signed native Wine client.
     * Checking /proc/self/exe avoids misrouting the supervisor, wineserver,
     * Java process, other app processes and arbitrary user executables. */
    char actual[PATH_MAX];
    ssize_t n=readlink("/proc/self/exe",actual,sizeof actual-1);
    if(n<=0||(size_t)n>=sizeof actual) {v49024_probe("PROC_SELF_EXE_READLINK_FAILED",NULL);return NULL;}
    actual[n]='\0';
    if(!rm11_vnext_vulkan_policy(soname,native_dir,actual,manifest_verified)) {
        v49024_probe("WINE_CHILD_PROCESS_POLICY_REJECTED",NULL);
        return NULL;
    }
    v49024_probe("WINE_CHILD_PROCESS_POLICY_ACCEPTED",NULL);

    for(size_t i=0;i<sizeof signed_components/sizeof signed_components[0];i++)
        if(!signed_file_in_dir(native_dir,signed_components[i])) {
            v49024_probe("SIGNED_COMPONENT_MISSING_OR_UNREADABLE",signed_components[i]);
            return NULL;
        }
    v49024_probe("SIGNED_COMPONENTS_PRESENT",NULL);

    char ado_path[PATH_MAX], driver_root[PATH_MAX];
    const char *probe=getenv("RM11_V49025_DIAGNOSTIC_ADRENOTOOLS");
    const int diagnostic=probe && !strcmp(probe,"1");
    const char *library=diagnostic?"librm11_adrenotools_probe_v49025.so":"libadrenotools.so";
    if(diagnostic && !signed_file_in_dir(native_dir,library)) {
        v49024_probe("DIAGNOSTIC_ADRENOTOOLS_PROBE_LIBRARY_MISSING",NULL);
        return NULL;
    }
    n=snprintf(ado_path,sizeof ado_path,"%s/%s",native_dir,library);
    if(n<=0||(size_t)n>=sizeof ado_path) {v49024_probe("ADRENOTOOLS_PATH_TOO_LONG",NULL);return NULL;}
    n=snprintf(driver_root,sizeof driver_root,"%s/",native_dir);
    if(n<=0||(size_t)n>=sizeof driver_root) {v49024_probe("TURNIP_DRIVER_PATH_TOO_LONG",NULL);return NULL;}

    /* The old /vendor loader and temporary writable ImageFs are NEVER used.
     * Custom driver is under signed APK nativeLibraryDir, with slash appended
     * exactly as libadrenotools' upstream concatenation expects. */
    void *ado=dlopen(ado_path,RTLD_NOW|RTLD_LOCAL);
    if(!ado) {
        const char *error=dlerror();
        const char *reason=error&&strstr(error,"not found")?"LIBRARY_NOT_FOUND":
            error&&strstr(error,"Permission denied")?"PERMISSION_DENIED":
            error&&strstr(error,"undefined symbol")?"UNDEFINED_SYMBOL":"OTHER";
        v49024_probe("ADRENOTOOLS_DLOPEN_FAILED",reason);
        return NULL;
    }
    v49024_probe("ADRENOTOOLS_DLOPEN_SUCCEEDED",NULL);
    void *symbol=dlsym(ado,"adrenotools_open_libvulkan");
    rm11_adrenotools_open_fn open_custom=NULL;
    /* POSIX defines dlsym() for function symbols; avoid a non-ISO direct
       object-pointer to function-pointer cast in the host -pedantic gate. */
    if(!symbol || sizeof open_custom!=sizeof symbol) {
        v49024_probe("ADRENOTOOLS_API_SYMBOL_MISSING",NULL);return NULL;
    }
    memcpy(&open_custom,&symbol,sizeof open_custom);
    if(!open_custom) {v49024_probe("ADRENOTOOLS_API_NULL",NULL);return NULL;}
    enum {RM11_ADRENOTOOLS_DRIVER_CUSTOM=1};
    v49024_probe("ADRENOTOOLS_OPEN_LIBVULKAN_CALLED",NULL);
    void *result=open_custom(RTLD_NOW|RTLD_LOCAL,RM11_ADRENOTOOLS_DRIVER_CUSTOM,
                       NULL,native_dir,driver_root,"libvulkan_freedreno.so",
                       NULL,NULL);
    v49024_probe(result?"ADRENOTOOLS_HANDLE_OPENED":"ADRENOTOOLS_RETURNED_NULL",NULL);
    return result;
}
