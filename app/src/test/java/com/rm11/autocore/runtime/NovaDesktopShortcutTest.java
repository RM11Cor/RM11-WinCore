package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class NovaDesktopShortcutTest {
    @Test public void persistentLinksUseUniqueNamesAndResolve() throws Exception{
        Path home=Files.createTempDirectory("rm11-nova-links");
        NovaWorkspaceFiles store=new NovaWorkspaceFiles(home.toFile());
        File desktop=store.createFolder(store.directory(),"Desktop");
        Path exe=home.resolve("test game.exe");
        Files.write(exe,new byte[]{'M','Z'});
        File first=NovaDesktopShortcut.create(store,desktop,exe.toFile());
        File second=NovaDesktopShortcut.create(store,desktop,exe.toFile());
        assertTrue(NovaDesktopShortcut.isShortcut(first));
        assertNotEquals(first.getName(),second.getName());
        assertEquals(exe.toFile().getCanonicalPath(),
                NovaDesktopShortcut.resolve(first).getCanonicalPath());
        assertTrue(first.getName().endsWith(NovaDesktopShortcut.EXT));
    }

    @Test public void cannotCreateLinkOutsideWorkspaceOrFollowSymlink() throws Exception{
        Path home=Files.createTempDirectory("rm11-nova-safe");
        NovaWorkspaceFiles store=new NovaWorkspaceFiles(home.toFile());
        File desktop=store.createFolder(store.directory(),"Desktop");
        Path exe=home.resolve("app.exe");
        Files.write(exe,new byte[]{1,2,3});
        try{
            NovaDesktopShortcut.create(store,home.toFile(),exe.toFile());
            fail("Outside Nova workspace");
        }catch(IOException expected){}
        File original=NovaDesktopShortcut.create(store,desktop,exe.toFile());
        Path linked=desktop.toPath().resolve("trick.rm11link");
        Files.createSymbolicLink(linked,original.toPath());
        try{
            NovaDesktopShortcut.resolve(linked.toFile());
            fail("Symlink link");
        }catch(IOException expected){}
        assertTrue(Files.isRegularFile(original.toPath()));
    }
    @Test public void brokenMetadataDoesNotResolve()throws Exception{
        Path home=Files.createTempDirectory("rm11-nova-corrupt");
        NovaWorkspaceFiles store=new NovaWorkspaceFiles(home.toFile());
        File desktop=store.createFolder(store.directory(),"Desktop");
        Path bad=desktop.toPath().resolve("invalid.rm11link");
        Files.write(bad,"wrong".getBytes("UTF-8"));
        try{
            NovaDesktopShortcut.resolve(bad.toFile());
            fail("Broken shortcut");
        }catch(IOException expected){}
    }
}
