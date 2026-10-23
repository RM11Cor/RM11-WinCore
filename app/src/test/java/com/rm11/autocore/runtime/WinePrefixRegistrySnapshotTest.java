package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class WinePrefixRegistrySnapshotTest {
    private RuntimeLayout fakeLayout() throws Exception {
        Path tmp = Files.createTempDirectory("rm11-wine-reg-snapshot");
        RuntimeLayout p=new RuntimeLayout(tmp.resolve("files"),tmp.resolve("native"));
        Files.createDirectories(p.winePrefix);
        Files.write(p.winePrefixMarker(),new byte[]{1});
        Files.write(p.winePrefix.resolve("system.reg"),"system".getBytes());
        Files.write(p.winePrefix.resolve("user.reg"),"user".getBytes());
        return p;
    }

    @Test public void snapshotsOriginalAndRetainsItWithoutOverwriting() throws Exception {
        RuntimeLayout p = fakeLayout();
        assertTrue(WinePrefixRegistrySnapshot.backup(p).contains("BACKED_UP"));
        Files.write(p.winePrefix.resolve("system.reg"),"MODIFIED".getBytes());
        assertTrue(WinePrefixRegistrySnapshot.backup(p).contains("PREVIOUS_COMPLETE"));
        Path copy = p.winePrefix.resolve(".rm11-registry-before-winedatadir-v283/system.reg");
        assertEquals("system",new String(Files.readAllBytes(copy)));
    }

    @Test public void doesNotClobberInterruptedSnapshots() throws Exception {
        RuntimeLayout p = fakeLayout();
        Files.createDirectory(p.winePrefix.resolve(".rm11-registry-before-winedatadir-v283"));
        try {
            WinePrefixRegistrySnapshot.backup(p);
            fail("Must refuse incomplete preexisting backup");
        } catch (java.io.IOException expected) {
            assertTrue(expected.getMessage().contains("INCOMPLETE"));
        }
    }

    @Test public void rejectsUncommittedPrefix() throws Exception {
        RuntimeLayout p = fakeLayout();
        Files.delete(p.winePrefixMarker());
        try {
            WinePrefixRegistrySnapshot.backup(p);
            fail("Must reject uncommitted Wine prefix");
        } catch (java.io.IOException expected) {
            assertTrue(expected.getMessage().contains("UNTRUSTED_OR_UNCOMMITTED"));
        }
    }
}
