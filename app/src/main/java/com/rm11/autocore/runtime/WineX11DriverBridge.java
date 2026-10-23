package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.InputStream;

/**
 * Opt-in X11 Wine PE dependencies. These are not proof of a functional
 * native Bionic Xlib driver, X11 desktop or Android rendering.
 */
public final class WineX11DriverBridge {
    private static final String[] MODULES = {"imm32.dll", "winex11.drv"};
    private WineX11DriverBridge() {}

    public static String prepare(RuntimeLayout p) {
        StringBuilder out = new StringBuilder("RM11_X11_PE_DRIVER_BRIDGE_V279\n");
        for(String module : MODULES)
            out.append(module).append(": ").append(link(p,module)).append('\n');
        out.append(nativeClientReport(p));
        return out.toString();
    }

    private static String link(RuntimeLayout p, String name) {
        try {
            Path trusted = p.appFiles.toRealPath();
            Path dll = p.wineDllRoot.resolve("aarch64-windows").resolve(name);
            if(!Files.isRegularFile(dll, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(dll) < 4096) return "BUNDLED_PE_NOT_FOUND";
            Path actual = dll.toRealPath();
            if(!actual.startsWith(trusted)) return "BLOCKED_UNTRUSTED_SOURCE";
            try(InputStream in=Files.newInputStream(dll)) {
                if(in.read()!='M' || in.read()!='Z') return "BLOCKED_NOT_PE";
            }
            Path prefix = p.winePrefix.toRealPath();
            Path system32 = p.winePrefix.resolve("drive_c/windows/system32");
            if(!prefix.startsWith(trusted)
                    || !Files.isRegularFile(p.winePrefixMarker(),LinkOption.NOFOLLOW_LINKS)
                    || !Files.isDirectory(system32,LinkOption.NOFOLLOW_LINKS)
                    || !system32.toRealPath().startsWith(prefix))
                return "BLOCKED_UNTRUSTED_PREFIX";
            Path dest=system32.resolve(name);
            if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS)) {
                if(Files.isSymbolicLink(dest) && dest.toRealPath().equals(actual))
                    return "READY_EXISTING_TRUSTED_LINK";
                return "EXISTING_FILE_OR_ALIAS_PRESERVED";
            }
            Files.createSymbolicLink(dest,actual);
            return Files.isRegularFile(dest) && dest.toRealPath().equals(actual)
                    ? "READY_NEW_TRUSTED_LINK" : "LINK_CREATED_NOT_READABLE";
        } catch(Exception error) {
            return "BLOCKED_"+error.getClass().getSimpleName();
        }
    }

    /**
     * Probe ONLY configured app-private candidate locations, not the system
     * linker namespace. "Missing" means NOT bundled here, never evidence that
     * Android has no libX11 anywhere or that dlopen failed in a process.
     */
    public static String nativeClientReport(RuntimeLayout p) {
        Path[] roots={p.imageFs.resolve("usr/lib"),p.wineRoot.resolve("lib"),p.apkNativeLibs};
        boolean x11=false, xext=false;
        for(Path root : roots) {
            x11 |= Files.isRegularFile(root.resolve("libX11.so.6"))
                    || Files.isRegularFile(root.resolve("libX11.so"));
            xext |= Files.isRegularFile(root.resolve("libXext.so.6"))
                    || Files.isRegularFile(root.resolve("libXext.so"));
        }
        boolean elf=Files.isRegularFile(p.wineDllRoot.resolve("aarch64-unix/winex11.so"));
        return "Wine winex11 Unix driver file: "+(elf?"PRESENT_UNVERIFIED":"MISSING")+"\n"
              +"libX11 client in configured bundled paths: "+(x11?"FOUND_UNVERIFIED":"NOT_BUNDLED")+"\n"
              +"libXext client in configured bundled paths: "+(xext?"FOUND_UNVERIFIED":"NOT_BUNDLED")+"\n"
              +"Bionic dlopen(winex11.so): NOT_TESTED\n"
              +"Wine-to-XServer display driver initialized: NOT_VERIFIED\n";
    }
}
