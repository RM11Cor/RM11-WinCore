package com.rm11.autocore.runtime;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Launch variables for a coherent Bionic ARM64EC + FEX/WoW64 installation.
 *  Native execution/re-exec redirector and the IPC supervisor remain separate components.
 */
public final class BionicLaunchEnvironment {
    private BionicLaunchEnvironment() {}

    public static Map<String, String> forFex(RuntimeLayout p) {
        RuntimeAssessment.inspect(p).requireReady();
        Map<String, String> env = new LinkedHashMap<>();
        String usr = p.imageFs.resolve("usr").toString();
        String nativeLib = p.apkNativeLibs.toString();
        env.put("HOME", p.imageFs.resolve("home/xuser").toString());
        env.put("USER", "xuser");
        env.put("TMPDIR", p.imageFs.resolve("usr/tmp").toString());
        env.put("WINEPREFIX", p.winePrefix.toString());
        env.put("PREFIX", usr);
        env.put("PATH", p.wineRoot.resolve("bin") + ":" + usr + "/bin");
        env.put("LD_LIBRARY_PATH", usr + "/lib:" + p.wineRoot.resolve("lib") + ":" + p.wineDllRoot.resolve("aarch64-unix") + ":" + nativeLib + ":/system/lib64");
        env.put("XDG_DATA_DIRS", p.wineShare.toString());
        env.put("WINE_DATADIR", p.wineShare.resolve("wine").toString());
        // Wine's Unix ntdll derives NLS data from the actual APK .so path; the
        // preloaded APK-native shim transparently redirects read-only NLS opens.
        env.put("RM11_WINE_DATADIR", p.wineShare.resolve("wine").toString());
        // Wine 11 discovers PE builtin paths from the APK-hosted native ntdll's
        // dladdr() location. The signed NLS preload safely bridges read-only PE
        // queries to our pinned, app-private ImageFs runtime; no writable APK aliases.
        env.put("RM11_APK_NATIVE_LIB_DIR", p.apkNativeLibs.toString());
        env.put("RM11_WINE_PE_DIR", p.wineDllRoot.resolve("aarch64-windows").toString());
        env.put("LD_PRELOAD", p.apkNativeLibs.resolve("librm11_wine_data_redirect.so").toString());
        env.put("XDG_CONFIG_DIRS", usr + "/etc/xdg");
        env.put("WINEDLLPATH", p.wineDllRoot.toString());
        env.put("WINESERVER", p.nativeWineServer.toString());
        env.put("HODLL64", "libarm64ecfex.dll");
        env.put("HODLL", "libwow64fex.dll");
        env.put("WINEDEBUG", "-all");
        // Deliberately no WINELOADERNOEXEC / DISPLAY defaults.
        // Those depend on a *verified* native exec/re-exec redirector and display/IPC service.
        return Collections.unmodifiableMap(env);
    }
}
