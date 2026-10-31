package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;
public class R4WitcherDx12LayoutV49075Test {
    @Test public void maintainsRelativeContentAndDlcPathsWithoutModifyingGame()throws Exception{
        Path td=Files.createTempDirectory("r4-v49075");
        Path game=td.resolve("original");
        Path exe=game.resolve("bin/x64_dx12/witcher3.exe");
        Files.createDirectories(exe.getParent());
        Files.createDirectories(game.resolve("content"));
        Files.createDirectories(game.resolve("dlc"));
        Files.createDirectories(game.resolve("bin/config"));
        Files.write(exe,new byte[]{'M','Z',1,2});
        Path side=td.resolve("private/runtime-123");
        R4WitcherDx12LayoutV49075.Paths layout=
            R4WitcherDx12LayoutV49075.mirror(exe,side);
        assertEquals(side.resolve("bin/x64_dx12/witcher3.exe"),layout.localExe());
        assertEquals(side.resolve("content"),layout.localContent());
        assertTrue(Files.isSymbolicLink(side.resolve("content")));
        assertTrue(Files.isSymbolicLink(side.resolve("dlc")));
        assertTrue(Files.isSymbolicLink(side.resolve("bin/config")));
        assertEquals(game.resolve("content").toRealPath(),
            layout.localContent().toRealPath());
        assertEquals(game.resolve("bin/config").toRealPath(),
            side.resolve("bin/config").toRealPath());
        assertTrue(Files.isRegularFile(exe));
        assertFalse(Files.exists(layout.localExe()));
    }
    @Test public void refusesNonWitcherGameLayouts()throws Exception{
        Path td=Files.createTempDirectory("r4-v49075-other");
        try{
            R4WitcherDx12LayoutV49075.plan(
                td.resolve("Silksong.exe"),td.resolve("stage"));
            fail("Must reject non-Witcher games");
        }catch(java.io.IOException good){
            assertEquals("NOT_A_WITCHER3_DX12_EXE",good.getMessage());
        }
    }
}
