package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
public class R4PrimaryExePathV49076Test {
    @Test public void alwaysStartsRootAndListsFoldersThenExecutables()throws Exception{
        Path root=Files.createTempDirectory("r4-picker");
        Path sub=Files.createDirectories(root.resolve("Games/Witcher 3/bin/x64_dx12"));
        Path exe=sub.resolve("witcher3.exe");
        Files.write(exe,new byte[1024]);
        Files.write(sub.resolve("readme.txt"),new byte[1024]);
        Files.write(root.resolve("silksong.exe"),new byte[1024]);
        List<R4PrimaryExePathV49076.Entry> atRoot=
            R4PrimaryExePathV49076.entries(root,root);
        assertEquals("Games",atRoot.get(0).path.getFileName().toString());
        assertTrue(atRoot.get(0).directory);
        assertEquals("silksong.exe",atRoot.get(1).path.getFileName().toString());
        assertTrue(R4PrimaryExePathV49076.validExe(root,exe));
        assertEquals(root.toRealPath(),
            R4PrimaryExePathV49076.parent(root,root));
        assertTrue(R4PrimaryExePathV49076.sourceEvidence(root,exe)
            .contains("R4_V49076_LIBRARY_PERSISTS_FULL_CANONICAL_EXE_PATH=true"));
    }
    @Test public void deniesOutsideAndSymlinkEscape()throws Exception{
        Path root=Files.createTempDirectory("r4-safe");
        Path outside=Files.createTempDirectory("r4-other");
        Path exe=outside.resolve("other.exe");
        Files.write(exe,new byte[4096]);
        assertFalse(R4PrimaryExePathV49076.validExe(root,exe));
        Path fake=root.resolve("escape.exe");
        Files.createSymbolicLink(fake,exe);
        assertFalse(R4PrimaryExePathV49076.validExe(root,fake));
        assertTrue(R4PrimaryExePathV49076.entries(root,root).isEmpty());
    }
}
