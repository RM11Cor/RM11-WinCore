package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineShellMenuBootstrapTest {
    @Test public void genuineLnkAndPreservation() throws Exception {
        Path tmp=Files.createTempDirectory("rm11-shell");
        RuntimeLayout r=new RuntimeLayout(tmp,tmp.resolve("native"));
        Path user=r.winePrefix.resolve("drive_c/users/xuser");
        Files.createDirectories(user);
        Files.write(r.winePrefixMarker(),new byte[]{1});
        Files.write(user.resolve("notes.txt"),new byte[]{42});
        String first=WineShellMenuBootstrap.stage(r);
        assertTrue(first,first.contains("MENU_LINKS_CREATED=6"));
        Path link=user.resolve("Desktop/RM11 Computer.lnk");
        assertTrue(Files.isRegularFile(link,LinkOption.NOFOLLOW_LINKS));
        byte[] bytes=Files.readAllBytes(link);
        assertTrue(bytes.length>76);
        assertEquals(76,bytes[0]&255);
        assertEquals(0,bytes[1]&255);
        assertTrue(WineShellMenuBootstrap.stage(r).contains("MENU_LINKS_CREATED=0"));
        assertEquals(42,Files.readAllBytes(user.resolve("notes.txt"))[0]);
    }
    @Test public void neverModifiesUnpreparedPrefix() throws Exception {
        Path tmp=Files.createTempDirectory("rm11-shell-empty");
        RuntimeLayout r=new RuntimeLayout(tmp,tmp.resolve("native"));
        assertTrue(WineShellMenuBootstrap.stage(r).contains("PREFIX_NOT_READY"));
        assertFalse(Files.exists(r.winePrefix.resolve("drive_c")));
    }
}
