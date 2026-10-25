package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.io.File;

public class NovaWorkspaceFilesTest {
    private NovaWorkspaceFiles prepare(Path base)throws Exception{
        Files.createDirectories(base.resolve("imagefs/home/xuser/.wine/drive_c"));
        return new NovaWorkspaceFiles(base.toFile());
    }
    @Test public void createsAndCopiesAndMovesWithoutOverwriting()throws Exception{
        Path root=Files.createTempDirectory("nova-writable");
        NovaWorkspaceFiles w=prepare(root);
        Path folder=w.createFolder(w.directory(),"Games").toPath();
        Path created=w.createFile(folder.toFile(),"notes.txt").toPath();
        Files.write(created,"safe-content".getBytes("UTF-8"));
        Path from=root.resolve("imagefs/home/xuser/.wine/drive_c/source.ini");
        Files.write(from,"source-content".getBytes("UTF-8"));
        assertTrue(Files.exists(w.copyFile(from.toFile(),folder.toFile()).toPath()));
        try{w.copyFile(from.toFile(),folder.toFile());fail("No overwrite");}
        catch(IOException ok){assertTrue(ok.getMessage().contains("EXISTS"));}
        assertEquals("safe-content",new String(Files.readAllBytes(
                w.rename(created.toFile(),"renamed.txt").toPath()),"UTF-8"));
        assertFalse(w.canEdit(from.toFile()));
        Path moved=w.moveFile(folder.resolve("renamed.txt").toFile(),
                w.directory()).toPath();
        assertTrue(Files.exists(moved));
        w.delete(moved.toFile());assertFalse(Files.exists(moved));
    }
    @Test public void protectsWineAndNonemptyFolders() throws Exception {
        Path base=Files.createTempDirectory("nova-protect");
        NovaWorkspaceFiles w=prepare(base);
        Path protectedWine=base.resolve("imagefs/home/xuser/.wine/drive_c/windows");
        Files.createDirectory(protectedWine);
        assertFalse(w.canEdit(protectedWine.toFile()));
        try{w.delete(protectedWine.toFile());fail("Must protect Wine");}
        catch(IOException expected){}
        Path own=w.createFolder(w.directory(),"Keep").toPath();
        Files.write(own.resolve("saved.bin"),new byte[]{1,2,3});
        try{w.delete(own.toFile());fail("Must not recursive-delete");}
        catch(IOException expected){}
        assertTrue(Files.exists(own.resolve("saved.bin")));
        try{w.createFile(w.directory(),"../escape");fail("Invalid name");}
        catch(IOException expected){}
    }
    @Test public void blocksSymlinkEscapeAndOversizeCopies() throws Exception {
        Path base=Files.createTempDirectory("nova-links");
        NovaWorkspaceFiles w=prepare(base);
        Path outside=Files.createTempFile("outside",".bin");
        Path link=w.directory().toPath().resolve("escape");
        Files.createSymbolicLink(link,outside);
        assertFalse(w.canEdit(link.toFile()));
        try{w.delete(link.toFile());fail("Symlink protected");}
        catch(IOException expected){}
        assertTrue(Files.exists(outside));
        Path huge=base.resolve("huge.bin");
        try(java.io.RandomAccessFile raf=new java.io.RandomAccessFile(huge.toFile(),"rw")){
            raf.setLength(256L*1024*1024+1);
        }
        try{w.copyFile(huge.toFile(),w.directory());fail("Over size");}
        catch(IOException ok){assertTrue(ok.getMessage().contains("256MB"));}
        assertFalse(Files.exists(w.directory().toPath().resolve("huge.bin")));
    }
    @Test public void phoneDSourceCopiesReadOnlyButNeverOutsideAuthorizedD()throws Exception {
        Path base=Files.createTempDirectory("rm11-d-drive");
        NovaWorkspaceFiles store=prepare(base.resolve("app"));
        Path phone=Files.createDirectories(base.resolve("Ddrive"));
        Path source=phone.resolve("Game Setup.exe");
        byte[] bytes=new byte[]{'M','Z',1,2,3};
        Files.write(source,bytes);
        File imported=store.copyFromPhone(source.toFile(),store.directory(),phone.toFile());
        assertArrayEquals(bytes,Files.readAllBytes(imported.toPath()));
        assertArrayEquals(bytes,Files.readAllBytes(source));
        try{
            store.copyFromPhone(source.toFile(),store.directory(),phone.toFile());
            fail("No overwrite");
        }catch(IOException expected){}
        Path outside=base.resolve("outside.exe");
        Files.write(outside,bytes);
        try{
            store.copyFromPhone(outside.toFile(),store.directory(),phone.toFile());
            fail("No path outside D");
        }catch(IOException expected){}
        assertArrayEquals(bytes,Files.readAllBytes(outside));
    }

}
