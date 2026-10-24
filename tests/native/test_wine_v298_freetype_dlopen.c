/* RM11 v2.9.8: verify FreeType dlopen target is strictly gated to embedded GUI.
 * Host-only synthetic FreeType; real ARM64 is verified by package manifest. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv) {
    if(argc!=3)return 70;
    void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if(!strcmp(argv[2],"present")) {
        if(!h){fprintf(stderr,"RM11_V298_FONT_MISSING:%s\n",dlerror());return 71;}
        int (*test)(void)=(int(*)(void))dlsym(h,"RM11_v298_test_FT");
        if(!test||test()!=298)return 72;
        puts("RM11_V298_AUDITED_FREETYPE_BRIDGE_TEST_SUCCEEDED");
        return 0;
    }
    /* CI hosts may already provide genuine system FreeType. The sentinel
     * export is unique to our signed test fixture: verify it was not loaded. */
    if(h) {
        void *unexpected=dlsym(h,"RM11_v298_test_FT");
        dlclose(h);
        if(unexpected){puts("RM11_V298_UNTRUSTED_FONT_REDIRECTED");return 73;}
    }
    puts("RM11_V298_FOREIGN_OR_DISABLED_DLOPEN_UNCHANGED");
    return 0;
}
