package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
import java.nio.file.Path;
public class R4Vkd3dV49073Test {
    @Test public void recognizesOnlyWitcherDx12ExePath(){
        assertTrue(R4Vkd3dV49073.isWitcherDx12(
            Path.of("/games/Witcher 3/bin/x64_dx12/witcher3.exe")));
        assertFalse(R4Vkd3dV49073.isWitcherDx12(
            Path.of("/games/Witcher 3/bin/x64/witcher3.exe")));
        assertFalse(R4Vkd3dV49073.isWitcherDx12(
            Path.of("/games/Silksong/Hollow Knight Silksong.exe")));
    }
    @Test public void dx12OverridesKeepUnrelatedControllerDlls(){
        String result=R4WineDllOverridesV49067.forDx12(
            "xinput1_4=n,b;d3d11,dxgi=b;foo=n,b;d3d12=b");
        assertTrue(result.contains("xinput1_4=n,b"));
        assertTrue(result.contains("foo=n,b"));
        assertTrue(result.contains("d3d12,d3d12core,dxgi=n,b"));
        assertFalse(result.contains("d3d12=b"));
    }
}
