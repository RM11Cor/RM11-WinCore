package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineStaticImportLinkerTest {
    private static void put16(byte[] b,int off,int x) {
        b[off]=(byte)x; b[off+1]=(byte)(x>>>8);
    }
    private static void put32(byte[] b,int off,int x) {
        for(int i=0;i<4;i++)b[off+i]=(byte)(x>>>(8*i));
    }
    /** Small valid PE64 sample containing one section and bounded import table. */
    private static byte[] pe64(int machine, String... imports) {
        byte[] b=new byte[8192];
        b[0]='M';b[1]='Z';put32(b,0x3c,0x80);
        b[0x80]='P';b[0x81]='E';
        put16(b,0x84,machine);
        put16(b,0x86,1);  // section count
        put16(b,0x94,0xf0); // optional size
        put16(b,0x98,0x20b); // PE32+
        // optional header import directory entry
        if(imports.length>0)put32(b,0x98+112+8,0x1000);
        int section=0x80+24+0xf0;
        put32(b,section+12,0x1000); // virtual addr
        put32(b,section+16,0x400); // raw size
        put32(b,section+20,0x400); // raw file ptr
        for(int i=0;i<imports.length;i++) {
            int descriptor=0x400+i*20;
            int nameRva=0x1100+i*48;
            put32(b,descriptor+12,nameRva);
            byte[] name=imports[i].getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(name,0,b,0x500+i*48,name.length);
        }
        return b;
    }
    private static RuntimeLayout setup(Path temp) throws Exception {
        Path app=temp.resolve("app"),nativeDir=temp.resolve("native");
        Files.createDirectories(app);Files.createDirectories(nativeDir);
        RuntimeLayout r=new RuntimeLayout(app,nativeDir);
        Files.createDirectories(r.wineDllRoot.resolve("aarch64-windows"));
        Files.createDirectories(r.winePrefix.resolve("drive_c/windows/system32"));
        Files.createDirectories(r.appFiles.resolve("external-exe-pilot"));
        Files.write(r.winePrefixMarker(),new byte[]{1});
        return r;
    }
    private static Path external(RuntimeLayout p,String... imports) throws Exception {
        Path exe=p.appFiles.resolve("external-exe-pilot/rm11-import-user.exe");
        Files.write(exe,pe64(0x8664,imports));
        return exe;
    }
    private static void wineDll(RuntimeLayout p,String name,String... imports) throws Exception {
        Files.write(p.wineDllRoot.resolve("aarch64-windows").resolve(name),
                pe64(0xaa64,imports));
    }
    @Test public void followsRealTransitiveWineArm64ImportsWithoutCycles() throws Exception {
        RuntimeLayout p=setup(Files.createTempDirectory("rm11-import-graph-"));
        Path exe=external(p,"user32.dll");
        wineDll(p,"user32.dll","ucrtbase.dll","advapi32.dll");
        wineDll(p,"ucrtbase.dll");
        wineDll(p,"advapi32.dll","sechost.dll");
        wineDll(p,"sechost.dll","user32.dll");
        String status=WineStaticImportLinker.prepare(p,exe);
        assertTrue(status,status.contains("result=BOUNDED_SCAN_COMPLETED"));
        assertTrue(status,status.contains("linked=4"));
        Path sys32=p.winePrefix.resolve("drive_c/windows/system32");
        for(String n:new String[]{"user32.dll","ucrtbase.dll","advapi32.dll","sechost.dll"}) {
            assertTrue(n,Files.isSymbolicLink(sys32.resolve(n)));
            assertEquals(p.wineDllRoot.resolve("aarch64-windows").resolve(n).toRealPath(),
                    sys32.resolve(n).toRealPath());
        }
        assertTrue(WineStaticImportLinker.prepare(p,exe).contains("existingTrusted=4"));
    }
    @Test public void neverReplacesExistingPrefixFile() throws Exception {
        RuntimeLayout p=setup(Files.createTempDirectory("rm11-import-preserve-"));
        Path exe=external(p,"advapi32.dll");
        wineDll(p,"advapi32.dll","sechost.dll");
        Path alias=p.winePrefix.resolve("drive_c/windows/system32/advapi32.dll");
        Files.write(alias,new byte[]{9,8,7});
        String report=WineStaticImportLinker.prepare(p,exe);
        assertTrue(report,report.contains("EXISTING_FILE_PRESERVED advapi32.dll"));
        assertArrayEquals(new byte[]{9,8,7},Files.readAllBytes(alias));
        assertFalse(Files.exists(alias.getParent().resolve("sechost.dll")));
    }
    @Test public void reportsNonBundledDllWithoutCreatingIt() throws Exception {
        RuntimeLayout p=setup(Files.createTempDirectory("rm11-import-missing-"));
        Path exe=external(p,"custom32.dll");
        String report=WineStaticImportLinker.prepare(p,exe);
        assertTrue(report,report.contains("NOT_BUNDLED custom32.dll"));
        assertFalse(Files.exists(p.winePrefix.resolve("drive_c/windows/system32/custom32.dll")));
    }
}
