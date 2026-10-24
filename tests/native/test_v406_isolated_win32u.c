/* v4.0.6 host integration check of the existing LD_PRELOAD interposer.
 * This is intentionally a fake Wine win32u ELF pair. The real ARM64
 * win32u rodata transformation is tested against signed v4.0.5 separately.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv) {
    if(argc!=3)return 60;
    void *handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if(!handle) {
        fprintf(stderr,"RM11_V406_HOST_DLOPEN_ERROR=%s\n",dlerror());
        return 61;
    }
    int (*which)(void)=(int(*)(void))dlsym(handle,"rm11_v406_test_wine_win32u");
    if(!which)return 62;
    int expected=atoi(argv[2]);
    if(expected!=405 && expected!=406)return 63;
    if(which()!=expected)return 64;
    puts(expected==406?"RM11_V406_CLIENT_ONLY_SIGNED_WIN32U_SELECTED":
                       "RM11_V406_ORIGINAL_WIN32U_UNCHANGED");
    return 0;
}
