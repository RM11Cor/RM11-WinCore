/* Host-side regression for Wine NTDLL dladdr relocation interposer only.
 * Run from ci/wine-v292-smoke.sh, no device or actual Wine binaries needed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
    if(argc!=4) return 90;
    void *handle=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL);
    if(!handle) { fprintf(stderr,"dlopen failed: %s\n",dlerror()); return 91; }
    void *value=dlsym(handle,"rm11_v292_test_symbol");
    Dl_info info;
    if(!value || !dladdr(value,&info)) return 92;
    printf("RM11_V292_DLADDR_ACTUAL_OR_VIRTUAL=%s\n",info.dli_fname);
    if(strcmp(info.dli_fname,argv[2])) return 93;
    void *host=dlsym(RTLD_DEFAULT,"printf");
    if(!host || !dladdr(host,&info) || strstr(info.dli_fname,argv[3])) return 94;
    puts("RM11_V292_SCOPED_DLADDR_MATCH_AND_UNRELATED_UNMODIFIED");
    return 0;
}
