package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Independent host Android / signed Bionic FreeType inspection.
 *
 * Never uses Wine's LD_PRELOAD, wineserver, FEX, user registry or the
 * target Windows process. A glyph rendered here proves only that the
 * signed NDK FreeType and bundled Tahoma work within Android; it does
 * NOT prove Wine's Wine32u text path or X11 glyph upload.
 */
public final class WineNativeFontProbe {
    private static volatile boolean loaded;
    private WineNativeFontProbe() {}

    private static native String probeNative(String signedFt, String fontTtf);
    private static native String probeLoaderNative(String signedFt);

    private static void ensureNativeLoaded(){
        if(!loaded){
            synchronized(WineNativeFontProbe.class){
                if(!loaded){
                    System.loadLibrary("rm11_wine_font_probe");
                    loaded=true;
                }
            }
        }
    }

    /**
     * Invoked only in separate :rm11_font_sandbox Android activity process.
     * Distinguishes a bare Wine SONAME lookup from a trusted absolute APK
     * JNI ELF lookup. Does not run Wine or enable any Wine font bridge.
     */
    public static String inspectLoaderBoundary(RuntimeLayout p){
        final String prefix="RM11_V445_ANDROID_FONT_LINKER: ";
        try{
            Path trusted=p.apkNativeLibs.toRealPath();
            Path ft=p.apkNativeLibs.resolve("librm11_freetype_core.so");
            if(!Files.isRegularFile(ft,LinkOption.NOFOLLOW_LINKS)
                    ||!Files.isReadable(ft)||Files.size(ft)<100000
                    ||!ft.toRealPath().startsWith(trusted))
                return prefix+"SIGNED_CORE_NOT_TRUSTED\n";
            ensureNativeLoaded();
            String result=probeLoaderNative(ft.toString());
            return prefix+(result==null?"JNI_NULL":result)+"\n";
        }catch(Exception | LinkageError failed){
            return prefix+"SAFE_FAILURE_"+failed.getClass().getSimpleName()+"\n";
        }
    }

    public static String inspect(RuntimeLayout p) {
        final String prefix="RM11_V302_ANDROID_FONT_PREFLIGHT: ";
        try {
            Path home=p.appFiles.toRealPath();
            Path nativeHome=p.apkNativeLibs.toRealPath();
            Path ft=p.apkNativeLibs.resolve("librm11_freetype_core.so");
            Path font=p.wineShare.resolve("wine/fonts/tahoma.ttf");
            if (!Files.isRegularFile(ft,LinkOption.NOFOLLOW_LINKS) ||
                    !Files.isReadable(ft) || Files.size(ft)<100000 ||
                    !ft.toRealPath().startsWith(nativeHome))
                return prefix+"SIGNED_FREETYPE_NOT_AVAILABLE\n";
            if (!Files.isRegularFile(font,LinkOption.NOFOLLOW_LINKS) ||
                    !Files.isReadable(font) || Files.size(font)<10000 ||
                    !font.toRealPath().startsWith(home))
                return prefix+"TRUSTED_TAHOMA_NOT_AVAILABLE\n";
            ensureNativeLoaded();
            String code=probeNative(ft.toString(),font.toString());
            return prefix+(code==null?"JNI_NO_RESULT":code)+"\n";
        } catch (Exception | LinkageError e) {
            return prefix+"SAFE_FAILURE_"+e.getClass().getSimpleName()+"\n";
        }
    }
}
