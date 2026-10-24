/* Host-side isolated smoke: signed Wine Unix winex11 path redirect only.
 * The actual driver and X server are tested on-device, not by this stub. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv){
    if(argc!=3) return 90;
    int should_pass=!strcmp(argv[2],"pass");
    void *h=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL);
    if(!should_pass){
        if(h){puts("RM11_V293_UNTRUSTED_DRIVER_REDIRECTED"); return 92;}
        puts("RM11_V293_UNTRUSTED_DRIVER_UNMODIFIED");
        return 0;
    }
    if(!h){fprintf(stderr,"signed driver not loaded: %s\n",dlerror());return 91;}
    int (*testfn)(void)=(int(*)(void))dlsym(h,"rm11_v293_test_driver_signed");
    if(!testfn || testfn()!=293) return 93;
    puts("RM11_V293_SIGNED_DRIVER_SELECTED_VERIFIED");
    return 0;
}
