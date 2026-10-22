package com.rm11.autocore.integration;

import com.rm11.autocore.runtime.RuntimeLayout;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Read-only audit of the two proposed RM11 runtime backends.
 * It never claims game compatibility from file presence and never launches Wine.
 */
public final class RuntimeIntegrationAudit {
    private RuntimeIntegrationAudit() {}

    private static boolean isFile(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
    }
    private static void check(List<String> lines, String name, Path path) {
        lines.add((isFile(path) ? "FOUND: " : "MISSING: ") + name + " -> " + path);
    }

    private static void nativeElf(List<String> lines, String name, Path path) {
        if (!isFile(path)) { lines.add("MISSING: " + name + " -> " + path); return; }
        try {
            Elf64Inspection.Result elf = Elf64Inspection.inspect(path);
            lines.add((elf.arm64 ? "ARM64: " : "WRONG_ABI: ") + name + " -> " + path);
            lines.add("  PT_INTERP: " + elf.interpreter);
            lines.add("  DT_NEEDED: " + (elf.needed.isEmpty() ? "(none declared)" : String.join(", ", elf.needed)));
        } catch (IOException e) {
            lines.add("INVALID_ELF: " + name + " (" + e.getMessage() + ")");
        }
    }

    /** Call on a worker thread; this only inspects existing files. */
    public static String report(RuntimeLayout p) {
        if (p == null) throw new IllegalArgumentException("Layout required");
        List<String> lines = new ArrayList<>();
        lines.add("RM11 integration audit v1 | READ ONLY | NOT A GAME LAUNCH TEST");
        lines.add("BIONIC_ARM64EC_FEX (current project backend)");
        nativeElf(lines,"native WineServer",p.nativeWineServer);
        nativeElf(lines,"native Wine launcher",p.nativeWineLauncher);
        nativeElf(lines,"native ntdll",p.nativeNtdll);
        check(lines,"Wine binary",p.wineRoot.resolve("bin/wine"));
        check(lines,"WineServer payload",p.wineRoot.resolve("bin/wineserver"));
        check(lines,"WoW64 FEX DLL",p.fexWow64());
        check(lines,"ARM64EC FEX DLL",p.fexArm64ec());
        check(lines,"Wine NLS table",p.wineNls);
        check(lines,"committed prefix marker",p.winePrefixMarker());
        lines.add("Prefix system32: " + Files.isDirectory(p.winePrefix.resolve("drive_c/windows/system32")));
        lines.add("Prefix dosdevices: " + Files.isDirectory(p.winePrefix.resolve("dosdevices")));
        // Diagnostic hint only. /etc/machine-id is not necessarily the fatal error.
        Path guestId = p.imageFs.resolve("etc/machine-id");
        lines.add("Guest machine-id: " + (isFile(guestId) ? "present" : "absent (not confirmed root cause)"));
        lines.add("Native child re-exec: NOT VERIFIED by this audit");
        lines.add("IPC/shared-memory/display: NOT VERIFIED by this audit");
        lines.add("");
        lines.add("GLIBC_BOX64 (separate future backend; never mixed with Bionic)");
        check(lines,"Box64 guest translator",p.imageFs.resolve("usr/local/bin/box64"));
        lines.add("glibc guest loader and proot/syscall bridge: NOT VERIFIED");
        lines.add("DO NOT launch unverified Linux binaries from app-private writable storage on Android 10+");
        lines.add("");
        lines.add("NEXT: resolve missing dependencies, choose ONE backend, validate IPC, then launch a small EXE.");
        return String.join("\n",lines);
    }
}
