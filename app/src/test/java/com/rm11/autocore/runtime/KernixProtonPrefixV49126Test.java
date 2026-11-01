package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.*;

public final class KernixProtonPrefixV49126Test {
    private static Path mockTemplate(Path app)throws Exception{
        Path source=KernixProtonFexInstallerV49121.slotRoot(app).resolve("prefix");
        Files.createDirectories(source.resolve("drive_c/windows/system32"));
        Files.createDirectories(source.resolve("dosdevices"));
        Files.createSymbolicLink(source.resolve("dosdevices/c:"),Path.of("../drive_c"));
        for(String name:new String[]{"system.reg","user.reg","userdef.reg"}){
            byte[] data=new byte[512];
            Files.write(source.resolve(name),data);
        }
        Files.write(source.resolve("drive_c/windows/system32/kernel32.dll"),
            new byte[512]);
        return source;
    }
    @Test public void copyKeepsTemplateUnchangedAndNeverReplacesWorkingState()
            throws Exception{
        Path app=Files.createTempDirectory("p11-copy-");
        Path source=mockTemplate(app);
        Path live=KernixProtonPrefixV49126.prepareDefault(app);
        assertFalse(live.equals(source));
        assertTrue(KernixProtonPrefixV49126.ready(app));
        assertTrue(Files.isSymbolicLink(live.resolve("dosdevices/c:")));
        assertFalse(Files.exists(live.resolve("dosdevices/e:"),
            LinkOption.NOFOLLOW_LINKS));
        Files.write(live.resolve("user.reg"),"changed-registry".getBytes());
        assertEquals(live,KernixProtonPrefixV49126.prepareDefault(app));
        assertEquals("changed-registry",
            new String(Files.readAllBytes(live.resolve("user.reg"))));
        assertEquals(512,Files.size(source.resolve("user.reg")));
    }
    @Test public void unownedExistingPrefixNeverOverwritten() throws Exception{
        Path app=Files.createTempDirectory("p11-unowned-");
        mockTemplate(app);
        Path live=KernixProtonPrefixV49126.writableRoot(app);
        Files.createDirectories(live);
        Files.write(live.resolve("preserve-user-data"),new byte[]{1,2,3});
        try{
            KernixProtonPrefixV49126.prepareDefault(app);
            fail("must not overwrite user state");
        }catch(java.io.IOException expected){
            assertTrue(Files.isRegularFile(live.resolve("preserve-user-data")));
        }
    }
    @Test public void foreignSymlinkInTemplateRejected() throws Exception{
        Path app=Files.createTempDirectory("p11-foreign-");
        Path src=mockTemplate(app);
        Files.createSymbolicLink(src.resolve("dosdevices/e:"),
            Path.of("/data/user/0/com.winlator.cmod"));
        try{
            KernixProtonPrefixV49126.prepareDefault(app);
            fail("foreign link accepted");
        }catch(java.io.IOException expected){
            assertFalse(Files.exists(KernixProtonPrefixV49126.writableRoot(app)));
        }
    }
}
