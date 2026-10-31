package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.Files;
import java.nio.file.Path;

public class KernixGameReadinessV49081Test {
    private Path exe(Path dir,String name)throws Exception{
        Files.createDirectories(dir);
        Path exe=dir.resolve(name);
        Files.write(exe,new byte[4096]);
        return exe;
    }
    @Test public void normalGameRetainsOriginalSourceAndIsNotDeclaredRendered()throws Exception{
        Path base=Files.createTempDirectory("kernix-source");
        Path game=exe(base.resolve("Games/Arbitrary"),"Runner.exe");
        KernixGameReadinessV49081.Result result=
            KernixGameReadinessV49081.inspect(game);
        assertTrue(result.canAttempt);
        assertEquals(KernixGameReadinessV49081.SOURCE_READY,result.status);
        assertFalse(result.assetWarning);
        assertFalse(result.evidence().contains(base.toString()));
        assertTrue(Files.isRegularFile(game));
    }
    @Test public void unityMissingDataWarnsWithoutBlocking()throws Exception{
        Path root=Files.createTempDirectory("kernix-unity");
        Path game=exe(root,"Game.exe");
        Files.write(root.resolve("UnityPlayer.dll"),new byte[8192]);
        KernixGameReadinessV49081.Result result=
            KernixGameReadinessV49081.inspect(game);
        assertTrue(result.canAttempt);
        assertTrue(result.assetWarning);
        assertEquals("UNITY_LAYOUT",result.kind);
        assertEquals(KernixGameReadinessV49081.ASSET_WARNING,result.status);
        Files.createDirectory(root.resolve("Game_Data"));
        assertFalse(KernixGameReadinessV49081.inspect(game).assetWarning);
    }
    @Test public void witcherRelativeContentIsLocatedAboveBinFolder()throws Exception{
        Path root=Files.createTempDirectory("kernix-witcher");
        Path exe=exe(root.resolve("bin/x64_dx12"),"witcher3.exe");
        assertTrue(KernixGameReadinessV49081.inspect(exe).assetWarning);
        Files.createDirectory(root.resolve("content"));
        KernixGameReadinessV49081.Result result=
            KernixGameReadinessV49081.inspect(exe);
        assertEquals("WITCHER3_DX12_LAYOUT",result.kind);
        assertTrue(result.canAttempt);
        assertFalse(result.assetWarning);
    }
    @Test public void missingExeIsOnlyHardStop()throws Exception{
        Path root=Files.createTempDirectory("kernix-missing");
        KernixGameReadinessV49081.Result r=
            KernixGameReadinessV49081.inspect(root.resolve("gone.exe"));
        assertFalse(r.canAttempt);
        assertEquals(KernixGameReadinessV49081.SOURCE_MISSING,r.status);
    }
}
