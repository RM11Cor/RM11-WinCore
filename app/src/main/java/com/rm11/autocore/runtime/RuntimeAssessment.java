package com.rm11.autocore.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** A structural preflight, NEVER proof of working Win32/FEX execution. */
public final class RuntimeAssessment {
    public enum State { BLOCKED, STRUCTURALLY_READY }
    private final List<String> blockers = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    private RuntimeAssessment() {}

    public static RuntimeAssessment inspect(RuntimeLayout p) {
        RuntimeAssessment r = new RuntimeAssessment();
        r.requireDirectory(p.imageFs.resolve("usr/bin"), "BIONIC_USR_BIN_MISSING");
        r.requireDirectory(p.imageFs.resolve("usr/lib"), "BIONIC_USR_LIB_MISSING");
        r.requireDirectory(p.imageFs.resolve("usr/share"), "BIONIC_USR_SHARE_MISSING");
        r.requireDirectory(p.imageFs.resolve("usr/tmp"), "BIONIC_TMP_MISSING");
        r.requireFile(p.wineNls, "NLS_TABLE_MISSING");
        r.requireFile(p.wineRoot.resolve("bin/wine"), "WINE_PACKAGE_MISSING");
        r.requireFile(p.wineRoot.resolve("bin/wineserver"), "WINESERVER_PACKAGE_MISSING");
        r.requireFile(p.unixNtdll(), "NTDLL_UNIX_MISSING");
        r.requireFile(p.fexArm64ec(), "ARM64EC_FEX_MISSING");
        r.requireFile(p.fexWow64(), "WOW64_FEX_MISSING");
        r.requireElfAarch64(p.nativeWineLauncher, "APK_WINE_LAUNCHER_INVALID");
        r.requireElfAarch64(p.nativeWineServer, "APK_WINESERVER_INVALID");
        r.requireElfAarch64(p.nativeNtdll, "APK_NTDLL_INVALID");
        // Creating WINEPREFIX as an empty directory is NOT initialization.
        r.requireDirectory(p.winePrefix.resolve("drive_c/windows/system32"), "PREFIX_WINDOWS_MISSING");
        r.requireFile(p.winePrefix.resolve("system.reg"), "PREFIX_SYSTEM_REG_MISSING");
        r.requireFile(p.winePrefix.resolve("user.reg"), "PREFIX_USER_REG_MISSING");
        r.requireDirectory(p.winePrefix.resolve("dosdevices"), "PREFIX_DOSDEVICES_MISSING");
        r.requireFile(p.winePrefixMarker(), "PREFIX_NOT_ATOMICALLY_COMMITTED");
        r.notes.add("This preflight DOES NOT establish process IPC, Win32 execution, or graphics support.");
        r.notes.add("No execution from app-private writable paths is authorized by this class.");
        return r;
    }

    private void requireFile(Path path, String code) {
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) blockers.add(code + ": " + path);
    }
    private void requireDirectory(Path path, String code) {
        if (!Files.isDirectory(path)) blockers.add(code + ": " + path);
    }
    private void requireElfAarch64(Path path, String code) {
        if (!Files.isRegularFile(path)) { blockers.add(code + " (not present): " + path); return; }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] h = new byte[20];
            int off = 0, count;
            while (off < h.length && (count = in.read(h, off, h.length-off)) != -1) off += count;
            boolean valid = off >= 20 && h[0]==0x7f && h[1]=='E' && h[2]=='L' && h[3]=='F'
                    && h[4]==2 && h[5]==1 && (h[18]&0xff)==183 && (h[19]&0xff)==0;
            if (!valid) blockers.add(code + " (not ELF64 AArch64): " + path);
        } catch (IOException ex) { blockers.add(code + " (unreadable): " + path); }
    }
    public State state() { return blockers.isEmpty() ? State.STRUCTURALLY_READY : State.BLOCKED; }
    public List<String> blockers() { return Collections.unmodifiableList(blockers); }
    public List<String> notes() { return Collections.unmodifiableList(notes); }
    public void requireReady() {
        if (state() != State.STRUCTURALLY_READY) throw new IllegalStateException(String.join("\n", blockers));
    }
}
