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
            if (!loaded) {
                synchronized (WineNativeFontProbe.class) {
                    if (!loaded) {
                        System.loadLibrary("rm11_wine_font_probe");
                        loaded=true;
                    }
                }
            }
            String code=probeNative(ft.toString(),font.toString());
            return prefix+(code==null?"JNI_NO_RESULT":code)+"\n";
        } catch (Exception | LinkageError e) {
            return prefix+"SAFE_FAILURE_"+e.getClass().getSimpleName()+"\n";
        }
    }
}
