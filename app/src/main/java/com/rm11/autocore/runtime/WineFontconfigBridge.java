package com.rm11.autocore.runtime;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * v4.0.9: private, bounded font catalogue for a user-clicked Winefile test.
 * Never use Android /system/fonts or Termux's hardcoded /data/data/com.termux.
 * No normal GUI/server environment is changed.
 */
public final class WineFontconfigBridge {
    private WineFontconfigBridge() {}

    public static boolean ready(RuntimeLayout p) {
        try {
            Path home=p.apkNativeLibs.toRealPath();
            Path nativeLib=p.apkNativeLibs.resolve("librm11_fc.so");
            Path fonts=p.wineShare.resolve("wine/fonts");
            Path driveFonts=p.winePrefix.resolve("drive_c/windows/Fonts");
            return !Files.isSymbolicLink(nativeLib)
                && Files.isRegularFile(nativeLib,LinkOption.NOFOLLOW_LINKS)
                && nativeLib.toRealPath().startsWith(home)
                && Files.size(nativeLib)>50000
                && Files.isDirectory(fonts)
                && fonts.toRealPath().startsWith(p.appFiles.toRealPath())
                && Files.isDirectory(driveFonts)
                && driveFonts.toRealPath().startsWith(p.appFiles.toRealPath());
        } catch(Exception e) { return false; }
    }

    public static Path prepare(RuntimeLayout p) throws java.io.IOException {
        if (!ready(p)) throw new java.io.IOException("RM11_V409_SIGNED_FONTCONFIG_OR_FONTS_MISSING");
        Path trustedRoot=p.appFiles.toRealPath();
        Path conf=p.appFiles.resolve("rm11-fontconfig-v409");
        Files.createDirectories(conf);
        if (!conf.toRealPath().startsWith(trustedRoot))
            throw new java.io.IOException("RM11_V409_FONTCONFIG_CONFIG_OUTSIDE_APP");
        Path cache=conf.resolve("cache");
        Files.createDirectories(cache);
        if(!cache.toRealPath().startsWith(trustedRoot))
            throw new java.io.IOException("RM11_V409_FONTCONFIG_CACHE_OUTSIDE_APP");
        Path wineFonts=p.wineShare.resolve("wine/fonts").toRealPath();
        Path windowsFonts=p.winePrefix.resolve("drive_c/windows/Fonts").toRealPath();
        String xml="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            +"<fontconfig>\n"
            +"  <dir>"+escape(wineFonts.toString())+"</dir>\n"
            +"  <dir>"+escape(windowsFonts.toString())+"</dir>\n"
            +"  <cachedir>"+escape(cache.toRealPath().toString())+"</cachedir>\n"
            +"</fontconfig>\n";
        Path target=conf.resolve("fonts.conf");
        if(Files.isSymbolicLink(target))
            throw new java.io.IOException("RM11_V409_FONTCONFIG_XML_SYMLINK_REJECTED");
        Files.write(target,xml.getBytes(StandardCharsets.UTF_8));
        return target;
    }

    private static String escape(String s) {
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;").replace("'","&apos;");
    }
}
