package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public final class WineBuiltinAliasBridgeTest {
    private RuntimeLayout layout(Path root) throws Exception {
        Path app = root.resolve("files");
        Path libs = root.resolve("native");
        Files.createDirectories(libs);
        RuntimeLayout p = new RuntimeLayout(app, libs);
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/system32"));
        Files.write(p.winePrefixMarker(), "COMPLETE".getBytes(StandardCharsets.US_ASCII));
        return p;
    }

    private Path createBuiltin(RuntimeLayout p, String name) throws Exception {
        Path dll=p.wineDllRoot.resolve("aarch64-windows").resolve(name);
        byte[] data=new byte[8192];
        data[0]='M';data[1]='Z';
        Files.write(dll, data);
        return dll;
    }

    @Test public void onlyLinksTrustedKernel32AndKernelbase() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-builtin-"));
        Path k32=createBuiltin(p,"kernel32.dll");
        Path kbase=createBuiltin(p,"kernelbase.dll");
        String status=WineBuiltinAliasBridge.prepare(p);
        assertTrue(status.contains("kernel32.dll: READY_NEW_LINK"));
        assertTrue(status.contains("kernelbase.dll: READY_NEW_LINK"));
        Path dir=p.winePrefix.resolve("drive_c/windows/system32");
        assertTrue(Files.isSymbolicLink(dir.resolve("kernel32.dll")));
        assertEquals(k32.toRealPath(),dir.resolve("kernel32.dll").toRealPath());
        assertEquals(kbase.toRealPath(),dir.resolve("kernelbase.dll").toRealPath());
        assertTrue(WineBuiltinAliasBridge.prepare(p).contains("kernel32.dll: READY_ALREADY_LINKED"));
    }

    @Test public void preservesExistingFiles() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-builtin-existing-"));
        createBuiltin(p,"kernel32.dll");
        createBuiltin(p,"kernelbase.dll");
        Path existing=p.winePrefix.resolve("drive_c/windows/system32/kernel32.dll");
        byte[] owned="PREEXISTING".getBytes(StandardCharsets.US_ASCII);
        Files.write(existing,owned);
        String result=WineBuiltinAliasBridge.prepare(p);
        assertTrue(result.contains("kernel32.dll: BLOCKED_EXISTING_ENTRY_PRESERVED"));
        assertArrayEquals(owned,Files.readAllBytes(existing));
        assertTrue(result.contains("kernelbase.dll: READY_NEW_LINK"));
    }

    @Test public void rejectsMissingAndNonPEFiles() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-builtin-invalid-"));
        Path broken=p.wineDllRoot.resolve("aarch64-windows/kernel32.dll");
        Files.write(broken, new byte[8192]);
        String status=WineBuiltinAliasBridge.prepare(p);
        assertTrue(status.contains("kernel32.dll: BLOCKED_INVALID_PE_HEADER"));
        assertTrue(status.contains("kernelbase.dll: UNMODIFIED_NoSuchFileException"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/system32/kernel32.dll")));
    }
}
