package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** Diagnoses the exact APK-derived PE search root and the ImageFs destination.
 * Does not mutate or repair anything, does not traverse user files or game folders.
 */
public final class WinePePathProbe {
    private WinePePathProbe() {}

    public static String report(RuntimeLayout p) {
        StringBuilder out = new StringBuilder("RM11_PE_DLL_PATH_PROBE_V261\n");
        Path pe = p.wineDllRoot.resolve("aarch64-windows");
        Path ntdll = pe.resolve("ntdll.dll");
        Path wineboot = pe.resolve("wineboot.exe");
        Path prefixNtdll = p.winePrefix.resolve("drive_c/windows/system32/ntdll.dll");
        Path prefixWineboot = p.winePrefix.resolve("drive_c/windows/system32/wineboot.exe");
        out.append("native APK source: ").append(p.apkNativeLibs).append('\n');
        out.append("PE ImageFs destination: ").append(pe).append('\n');
        out.append("Wine runtime root symlink: ").append(Files.isSymbolicLink(p.wineRoot)).append('\n');
        try {
            out.append("Wine runtime root target: ")
               .append(Files.exists(p.wineRoot) ? p.wineRoot.toRealPath() : "MISSING")
               .append('\n');
        } catch (Exception e) { out.append("Wine root resolution: ").append(e.getClass().getSimpleName()).append('\n'); }
        append(out, "PE ntdll.dll", ntdll);
        append(out, "PE wineboot.exe", wineboot);
        append(out, "Prefix system32 ntdll.dll", prefixNtdll);
        append(out, "Prefix system32 wineboot.exe", prefixWineboot);
        append(out, "APK native Wine ntdll.so", p.nativeNtdll);
        return out.toString();
    }

    private static void append(StringBuilder out, String label, Path file) {
        out.append(label).append(": ");
        try {
            boolean link = Files.isSymbolicLink(file);
            boolean isFile = Files.isRegularFile(file);
            out.append(isFile ? "PRESENT" : "MISSING_OR_NOT_REGULAR")
               .append(" symlink=").append(link);
            if (isFile) out.append(" bytes=").append(Files.size(file));
            out.append('\n');
        } catch (Exception e) {
            out.append(e.getClass().getSimpleName()).append('\n');
        }
    }
}
