package com.rm11.autocore.runtime;
import static org.junit.Assert.*;
import org.junit.Test;
public class R4AutoGraphicsV49071Test {
    @Test public void choosesDxvkOnlyWhenRuntimeAvailable(){
        assertEquals("DXVK",R4AutoGraphicsV49071.modeFor(
            "Direct3D 11 / DXGI (PE imports)","غير محدد",true,true,false,false));
        assertEquals("WINED3D",R4AutoGraphicsV49071.modeFor(
            "Direct3D 11 / DXGI (PE imports)","غير محدد",true,false,false,false));
        assertEquals("DXVK",R4AutoGraphicsV49071.modeFor(
            "غير محدد","Unity (قرائن ملفات)",true,true,false,false));
    }
    @Test public void doesNotPretendDxvkSupportsDx12OrProtectedGames(){
        assertEquals("WINED3D",R4AutoGraphicsV49071.modeFor(
            "Direct3D 12 (PE imports)","غير محدد",true,true,true,false));
        assertEquals("WINED3D",R4AutoGraphicsV49071.modeFor(
            "Direct3D 11 / DXGI (PE imports)","غير محدد",true,true,false,true));
        assertEquals("WINED3D",R4AutoGraphicsV49071.modeFor(
            "غير محدد","غير محدد",true,true,false,false));
    }
}
