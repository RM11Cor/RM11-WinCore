package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class R4WineDllOverridesV49067Test {
    @Test public void preservesControllerAndNonGraphicsFlags() {
        String s=R4WineDllOverridesV49067.forGameGraphics(
            "xinput1_3,xinput1_4=n,b;d3d11=b;dxgi=b;dinput8=n,b",true);
        assertEquals("xinput1_3,xinput1_4=n,b;dinput8=n,b;d3d11,dxgi=n,b",s);
    }

    @Test public void graphicsOnlyReplacementPreservesMixedGroup() {
        String s=R4WineDllOverridesV49067.forGameGraphics(
            "d3d11,xinput9_1_0,dxgi=n,b;winmm=b",false);
        assertEquals("xinput9_1_0=n,b;winmm=b;d3d11,dxgi=b",s);
    }

    @Test public void startsFromEmptyWithoutClobberingDefaults() {
        assertEquals("d3d11,dxgi=n,b",
            R4WineDllOverridesV49067.forGameGraphics(null,true));
        assertEquals("d3d11,dxgi=b",
            R4WineDllOverridesV49067.forGameGraphics("",false));
    }

    @Test public void modeSwitchDoesNotAccumulateGraphicsOverrides() {
        String original="xinput1_3=n,b;opengl32=b";
        String enabled=R4WineDllOverridesV49067.forGameGraphics(original,true);
        String disabled=R4WineDllOverridesV49067.forGameGraphics(enabled,false);
        assertEquals("xinput1_3=n,b;opengl32=b;d3d11,dxgi=b",disabled);
    }

    @Test public void unrelatedAndUnknownEntriesNotDiscarded() {
        String result=R4WineDllOverridesV49067.forGameGraphics(
            "custom;XINPUT1_4=n,b;D3D11.DLL=b;DxGi=b",true);
        assertEquals("custom;XINPUT1_4=n,b;d3d11,dxgi=n,b",result);
    }
}
