/*
 * RM11 v3.0.2: app-process-only read-only FreeType core/GDI glyph preflight.
 *
 * This code is NEVER LD_PRELOADed into Wine/wineserver. It loads the signed
 * original ARM64/Bionic FreeType ELF from app nativeLibraryDir in an ordinary
 * Android host library and probes a verified bundled original Tahoma font.
 * The test does not alter Wine's memory, registry, fonts or IPC.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#ifndef RM11_FONT_SELFTEST_HOST
#include <jni.h>
#endif

typedef void *FT_Library_Opaque;
typedef void *FT_Face_Opaque;
typedef int (*FT_Init_t)(FT_Library_Opaque *);
typedef int (*FT_New_Face_t)(FT_Library_Opaque,const char *,long,FT_Face_Opaque *);
typedef unsigned int (*FT_Get_Char_Index_t)(FT_Face_Opaque,unsigned long);
typedef int (*FT_Set_Pixel_Sizes_t)(FT_Face_Opaque,unsigned int,unsigned int);
typedef int (*FT_Load_Char_t)(FT_Face_Opaque,unsigned long,int32_t);
typedef int (*FT_Done_Face_t)(FT_Face_Opaque);
typedef int (*FT_Done_FreeType_t)(FT_Library_Opaque);

static void ft_inspect(const char *so, const char *ttf, char out[256]) {
    struct stat st;
    if (!so || !ttf || so[0]!='/' || ttf[0]!='/' ||
        stat(so,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<100000) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_SIGNED_ELF_MISSING");
        return;
    }
    if (stat(ttf,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<10000) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_TAHOMA_MISSING");
        return;
    }
    void *lib=dlopen(so,RTLD_NOW|RTLD_LOCAL);
    if (!lib) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_DLOPEN_FAILED");
        return;
    }
    FT_Init_t init=(FT_Init_t)dlsym(lib,"FT_Init_FreeType");
    FT_New_Face_t newface=(FT_New_Face_t)dlsym(lib,"FT_New_Face");
    FT_Get_Char_Index_t index=(FT_Get_Char_Index_t)dlsym(lib,"FT_Get_Char_Index");
    FT_Set_Pixel_Sizes_t sizes=(FT_Set_Pixel_Sizes_t)dlsym(lib,"FT_Set_Pixel_Sizes");
    FT_Load_Char_t load=(FT_Load_Char_t)dlsym(lib,"FT_Load_Char");
    FT_Done_Face_t doneface=(FT_Done_Face_t)dlsym(lib,"FT_Done_Face");
    FT_Done_FreeType_t done=(FT_Done_FreeType_t)dlsym(lib,"FT_Done_FreeType");
    if(!init||!newface||!index||!sizes||!load||!doneface||!done) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_REQUIRED_SYMBOL_MISSING");
        dlclose(lib);return;
    }
    FT_Library_Opaque library=NULL;
    FT_Face_Opaque face=NULL;
    int ret=init(&library);
    if(ret || !library) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_FT_INIT_ERROR_%d",ret);
        dlclose(lib);return;
    }
    ret=newface(library,ttf,0,&face);
    if(ret || !face) {
        snprintf(out,256,"RM11_V302_FONT_PROBE_TAHOMA_FACE_ERROR_%d",ret);
        done(library);dlclose(lib);return;
    }
    unsigned int glyph=index(face,(unsigned long)'A');
    int size_status=sizes(face,0,20);
    int load_status=size_status==0 && glyph!=0 ?
        load(face,(unsigned long)'A',4 /* FT_LOAD_RENDER */) : -1;
    if(!glyph)
        snprintf(out,256,"RM11_V302_FONT_PROBE_TAHOMA_GLYPH_INDEX_ZERO");
    else if(size_status)
        snprintf(out,256,"RM11_V302_FONT_PROBE_SET_PIXEL_SIZE_ERROR_%d",size_status);
    else if(load_status)
        snprintf(out,256,"RM11_V302_FONT_PROBE_RENDER_GLYPH_ERROR_%d",load_status);
    else
        snprintf(out,256,"RM11_V302_FONT_PROBE_NATIVE_GLYPH_A_RENDER_OK");
    doneface(face);
    done(library);
    dlclose(lib);
}

#ifdef RM11_FONT_SELFTEST_HOST
int main(int argc,char **argv) {
    char message[256]={0};
    if(argc!=3)return 2;
    ft_inspect(argv[1],argv[2],message);
    puts(message);
    return strstr(message,"_RENDER_OK")?0:1;
}
#else
JNIEXPORT jstring JNICALL
Java_com_rm11_autocore_runtime_WineNativeFontProbe_probeNative(
        JNIEnv *env, jclass clazz, jstring soPath, jstring fontPath) {
    (void)clazz;
    const char *so=(*env)->GetStringUTFChars(env,soPath,NULL);
    if(!so)return NULL;
    const char *ttf=(*env)->GetStringUTFChars(env,fontPath,NULL);
    if(!ttf) { (*env)->ReleaseStringUTFChars(env,soPath,so);return NULL; }
    char message[256]={0};
    ft_inspect(so,ttf,message);
    (*env)->ReleaseStringUTFChars(env,soPath,so);
    (*env)->ReleaseStringUTFChars(env,fontPath,ttf);
    return (*env)->NewStringUTF(env,message);
}
#endif
