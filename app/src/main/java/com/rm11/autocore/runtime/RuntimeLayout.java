package com.rm11.autocore.runtime;

import java.nio.file.Path;
import java.util.Objects;

/** File locations for a self-contained Android/Bionic Wine ARM64EC runtime.
 *  These files must NOT be executed out of writable app-private storage on targetSdk>=29.
 */
public final class RuntimeLayout {
    public final Path appFiles;
    public final Path apkNativeLibs;
    public final Path imageFs;
    public final Path wineRoot;
    public final Path winePrefix;
    public final Path wineDllRoot;
    public final Path wineShare;
    public final Path wineNls;
    public final Path nativeWineLauncher;
    public final Path nativeWineServer;
    public final Path nativeNtdll;

    public RuntimeLayout(Path appFiles, Path apkNativeLibs) {
        this.appFiles = Objects.requireNonNull(appFiles).toAbsolutePath().normalize();
        this.apkNativeLibs = Objects.requireNonNull(apkNativeLibs).toAbsolutePath().normalize();
        this.imageFs = this.appFiles.resolve("imagefs");
        this.wineRoot = imageFs.resolve("opt/wine");
        this.winePrefix = imageFs.resolve("home/xuser/.wine");
        this.wineDllRoot = wineRoot.resolve("lib/wine");
        this.wineShare = wineRoot.resolve("share");
        this.wineNls = wineShare.resolve("wine/nls/l_intl.nls");
        this.nativeWineLauncher = this.apkNativeLibs.resolve("libwineprobe.so");
        this.nativeWineServer = this.apkNativeLibs.resolve("libwineserverrm11.so");
        this.nativeNtdll = this.apkNativeLibs.resolve("libwine_ntdll.so");
    }

    public Path fexArm64ec() { return wineDllRoot.resolve("aarch64-windows/libarm64ecfex.dll"); }
    public Path fexWow64() { return wineDllRoot.resolve("aarch64-windows/libwow64fex.dll"); }
    public Path unixNtdll() { return wineDllRoot.resolve("aarch64-unix/ntdll.so"); }
    public Path winePrefixMarker() { return winePrefix.resolve(".rm11-prefix-complete"); }
}
