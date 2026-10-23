package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public final class WineFexAliasBridgeTest {
    private static final String FEX = "libarm64ecfex.dll";

    private RuntimeLayout layout(Path temp) throws Exception {
        Path app = temp.resolve("files");
        Path nativeLibs = temp.resolve("signed-apk-native-libs");
        Files.createDirectories(app);
        Files.createDirectories(nativeLibs);
        RuntimeLayout layout = new RuntimeLayout(app, nativeLibs);
        Files.createDirectories(layout.winePrefix.resolve("drive_c/windows/system32"));
        Files.createDirectories(layout.wineDllRoot.resolve("aarch64-windows"));
        return layout;
    }

    private Path createModule(RuntimeLayout p) throws Exception {
        Path module = p.wineDllRoot.resolve("aarch64-windows").resolve(FEX);
        byte[] data = new byte[5100];
        data[0] = 'M'; data[1] = 'Z';
        Files.write(module, data);
        return module;
    }

    @Test public void createsNonDestructiveAliasAndIsIdempotent() throws Exception {
        Path temp = Files.createTempDirectory("rm11-fex-");
        RuntimeLayout p = layout(temp);
        Path target = createModule(p);
        assertEquals("READY_NEW_LINK", WineFexAliasBridge.prepare(p));
        Path alias = p.winePrefix.resolve("drive_c/windows/system32").resolve(FEX);
        assertTrue(Files.isSymbolicLink(alias));
        assertEquals(target.toRealPath(), alias.toRealPath());
        assertEquals("READY_ALREADY_LINKED", WineFexAliasBridge.prepare(p));
        assertTrue(WineFexAliasBridge.status(p).contains("Alias resolves to bundled Wine module: true"));
    }

    @Test public void doesNotOverwriteExistingPrefixFile() throws Exception {
        Path temp = Files.createTempDirectory("rm11-fex-conflict-");
        RuntimeLayout p = layout(temp);
        createModule(p);
        Path alias = p.winePrefix.resolve("drive_c/windows/system32").resolve(FEX);
        Files.write(alias, "Existing user data".getBytes(StandardCharsets.UTF_8));
        assertEquals("BLOCKED_EXISTING_SYSTEM32_ENTRY", WineFexAliasBridge.prepare(p));
        assertEquals("Existing user data", new String(Files.readAllBytes(alias),StandardCharsets.UTF_8));
    }

    @Test public void refusesMissingModule() throws Exception {
        Path temp = Files.createTempDirectory("rm11-fex-absent-");
        RuntimeLayout p = layout(temp);
        String state=WineFexAliasBridge.prepare(p);
        assertTrue(state.startsWith("FAILED_") || state.equals("BLOCKED_MODULE_MISSING_OR_TOO_SMALL"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/system32").resolve(FEX)));
    }

    @Test public void rejectsNonPEModule() throws Exception {
        Path temp = Files.createTempDirectory("rm11-fex-invalid-");
        RuntimeLayout p = layout(temp);
        Path fake=p.wineDllRoot.resolve("aarch64-windows").resolve(FEX);
        Files.write(fake, new byte[5000]);
        assertEquals("BLOCKED_INVALID_PE_HEADER", WineFexAliasBridge.prepare(p));
    }
}
