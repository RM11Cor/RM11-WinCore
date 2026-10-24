package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public final class WineX11DriverBridgeTest {
    private RuntimeLayout layout() throws Exception {
        Path tmp=Files.createTempDirectory("rm11-x11-drv-test-");
        RuntimeLayout p=new RuntimeLayout(tmp.resolve("files"),tmp.resolve("apk"));
        Files.createDirectories(p.apkNativeLibs);
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(p.wineDllRoot.resolve("aarch64-unix"));
        Files.createDirectories(p.winePrefix.resolve("drive_c/windows/system32"));
        Files.write(p.winePrefixMarker(),new byte[]{1});
        return p;
    }
    private Path pe(RuntimeLayout p,String name) throws Exception {
        Path src=p.wineDllRoot.resolve("aarch64-windows").resolve(name);
        byte[] bytes=new byte[8192]; bytes[0]='M';bytes[1]='Z';
        Files.write(src,bytes);
        return src;
    }
    @Test public void createsOnlyPinnedMissingAliasesAndReportsMissingXlib() throws Exception {
        RuntimeLayout p=layout();
        Path a=pe(p,"imm32.dll");
        Path x=pe(p,"winex11.drv");
        String result=WineX11DriverBridge.prepare(p);
        assertTrue(result,result.contains("imm32.dll: READY_NEW_TRUSTED_LINK"));
        assertTrue(result,result.contains("winex11.drv: READY_NEW_TRUSTED_LINK"));
        assertTrue(result,result.contains("libX11 client in configured bundled paths: NOT_BUNDLED"));
        assertEquals(a.toRealPath(),p.winePrefix.resolve("drive_c/windows/system32/imm32.dll").toRealPath());
        assertEquals(x.toRealPath(),p.winePrefix.resolve("drive_c/windows/system32/winex11.drv").toRealPath());
        assertTrue(WineX11DriverBridge.prepare(p).contains("READY_EXISTING_TRUSTED_LINK"));
    }
    @Test public void refusesToOverwriteExistingPrefixAndAcceptsBundledLibX11AsPresenceOnly() throws Exception {
        RuntimeLayout p=layout();
        pe(p,"imm32.dll");
        pe(p,"winex11.drv");
        Path dest=p.winePrefix.resolve("drive_c/windows/system32/imm32.dll");
        Files.write(dest,new byte[]{12,42});
        Files.createDirectories(p.imageFs.resolve("usr/lib"));
        Files.write(p.imageFs.resolve("usr/lib/libX11.so.6"),new byte[]{1});
        String out=WineX11DriverBridge.prepare(p);
        assertTrue(out,out.contains("imm32.dll: EXISTING_FILE_OR_ALIAS_PRESERVED"));
        assertEquals(2L,Files.size(dest));
        assertTrue(out,out.contains("libX11 client in configured bundled paths: FOUND_UNVERIFIED"));
        assertTrue(out,out.contains("Bionic dlopen(winex11.so): NOT_TESTED"));
    }
    @Test public void missingExplorerSystem32IsLinkedToOriginalWinePeWithoutOverwriting() throws Exception {
        RuntimeLayout p=layout();
        pe(p,"imm32.dll");
        pe(p,"winex11.drv");
        Path original=pe(p,"explorer.exe");
        String first=WineX11DriverBridge.prepare(p);
        assertTrue(first,first.contains("explorer.exe: READY_NEW_TRUSTED_LINK"));
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/explorer.exe");
        assertTrue(Files.isSymbolicLink(alias));
        assertEquals(original.toRealPath(),alias.toRealPath());
        String again=WineX11DriverBridge.prepare(p);
        assertTrue(again,again.contains("explorer.exe: READY_EXISTING_TRUSTED_LINK"));
        Files.delete(alias);
        byte[] existing=new byte[]{9,8,7};
        Files.write(alias,existing);
        String preserved=WineX11DriverBridge.prepare(p);
        assertTrue(preserved,preserved.contains("explorer.exe: EXISTING_FILE_OR_ALIAS_PRESERVED"));
        assertArrayEquals(existing,Files.readAllBytes(alias));
    }
    @Test public void refusesUntrustedPeSource() throws Exception {
        RuntimeLayout p=layout();
        Path dll=p.wineDllRoot.resolve("aarch64-windows/imm32.dll");
        Files.write(dll,new byte[8192]);
        String out=WineX11DriverBridge.prepare(p);
        assertTrue(out,out.contains("imm32.dll: BLOCKED_NOT_PE"));
    }
}
