/* v2.4.19: AArch64 Android diagnostic executable, NOT a Windows game runtime.
   Packaged as libwineprobe.so to run from APK nativeLibraryDir on Android 10+.
   Native Wine's ntdll.so is packaged as libwine_ntdll.so to avoid loading
   unsigned/mutable ELF text from the app's writable private home directory. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    fprintf(stderr, "RM11 native Wine ntdll bridge v2.4.19: attempting dlopen(libwine_ntdll.so)\n");
    fflush(stderr);
    void *handle = dlopen("libwine_ntdll.so", RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        const char *error=dlerror();
        fprintf(stderr, "RM11_LINKER_ERROR: %s\n",error ? error : "no linker explanation");
        return 86;
    }
    fprintf(stderr, "RM11_NATIVE_NTDLL_DLOPEN_OK\n");
    fflush(stderr);
    dlerror();
    void *symbol=dlsym(handle,"__wine_main");
    const char *error=dlerror();
    if (!symbol || error) {
        fprintf(stderr,"RM11_SYMBOL_ERROR: %s\n", error ? error : "missing __wine_main");
        return 87;
    }
    fprintf(stderr, "RM11_WINE_ENTRY_FOUND; handing over to Wine\n");
    fflush(stderr);
    void (*entry)(int,char**)=(void(*)(int,char**))symbol;
    entry(argc,argv);
    fprintf(stderr,"RM11: Wine __wine_main returned unexpectedly\n");
    return 88;
}
