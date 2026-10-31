package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public class R4WitcherExecutableV49072Test {
    private File exe(Path root,String relative)throws Exception{
        Path p=root.resolve(relative);Files.createDirectories(p.getParent());
        byte[] b=new byte[1024];b[0]='M';b[1]='Z';Files.write(p,b);return p.toFile();
    }
    @Test public void preferRealDx11EvenIfUserPickedDx12OrRedLauncher()throws Exception{
        Path root=Files.createTempDirectory("rm11-witcher-dx11");
        File dx12=exe(root,"bin/x64_dx12/witcher3.exe");
        File dx11=exe(root,"bin/x64/witcher3.exe");
        File red=exe(root,"REDlauncher.exe");
        assertEquals(R4WitcherExecutableV49072.CLASSIC_DX11,
            R4WitcherExecutableV49072.resolve(dx12).status);
        assertEquals(dx11.getCanonicalFile(),
            R4WitcherExecutableV49072.resolve(red).executable);
        assertTrue(R4WitcherExecutableV49072.classicDx11(dx11));
    }
    @Test public void accuratelyBlocksDx12OnlyButNotOtherGames()throws Exception{
        Path root=Files.createTempDirectory("rm11-witcher-dx12");
        File dx12=exe(root,"bin/x64_dx12/witcher3.exe");
        File red=exe(root,"REDlauncher.exe");
        File silksong=exe(root,"Hollow Knight Silksong.exe");
        assertTrue(R4WitcherExecutableV49072.resolve(dx12).blocked());
        assertTrue(R4WitcherExecutableV49072.resolve(red).blocked());
        assertFalse(R4WitcherExecutableV49072.resolve(silksong).blocked());
    }
}
