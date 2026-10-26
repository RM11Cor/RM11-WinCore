/*
 * Host-only Linux process-boundary preflight of RM11's actual native
 * dlopen() interposer. Test binary is intentionally named like the signed
 * Android Wine launcher or wineserver to validate /proc/self/exe gating.
 * Never executes Wine or uses the user's Wine prefix.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv) {
    if(argc!=3)return 80;
    char *end=NULL;
    long expected=strtol(argv[2],&end,10);
    if(!end || *end!='\0' || (expected!=0 && expected!=444 && expected!=999))
        return 81;
    void *handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    int result=0;
    if(handle) {
        int (*sentinel)(void)=(int (*)(void))dlsym(handle,"RM11_v444_signed_font");
        if(sentinel)result=sentinel();
        dlclose(handle);
    }
    if(result!=expected) {
        fprintf(stderr,"RM11_V444_PROCESS_BOUNDARY_FAIL name=%s expected=%ld found=%d\n",
                argv[1],expected,result);
        return 82;
    }
    printf("RM11_V444_PROCESS_BOUNDARY_OK requested=%s marker=%d\n",
           argv[1],result);
    return 0;
}
