package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class KernixLaunchStackV49119Test {
    private static Map<String,String> baseline(){
        Map<String,String> env=new HashMap<>();
        env.put("HOME","/private/imagefs/home/xuser");
        env.put("USER","xuser");
        env.put("WINEPREFIX","/private/imagefs/home/xuser/.wine");
        env.put("WINESERVER","/signed/libwineserverrm11.so");
        env.put("HODLL64","libarm64ecfex.dll");
        env.put("HODLL","libwow64fex.dll");
        env.put("WINEDLLPATH","/private/opt/wine/lib/wine");
        env.put("RM11_WINE_PE_DIR","/private/opt/wine/lib/wine/aarch64-windows");
        env.put("DISPLAY","127.0.0.1:2");
        return env;
    }
    @Test public void gameGraphicsLibrariesStayAheadOfWinebusOnlyExtras()
            throws Exception{
        String actual=KernixLaunchStackV49119.mergeNativeLibraryPaths(
            "/game/vulkan:/wine/arm64:/signed",
            "/signed:/controller/SDL:/wine/arm64:/controller/SDL");
        assertEquals("/game/vulkan:/wine/arm64:/signed:/controller/SDL",actual);
        assertEquals("/private/lib:/bus/lib",
            KernixLaunchStackV49119.mergeNativeLibraryPaths(
                "/private/lib:","/bus/lib"));
    }
    @Test public void repairsHomeDriftAndSeparatesD3d12Renderer()throws Exception{
        Map<String,String> base=baseline(),game=new HashMap<>(base);
        game.put("HOME","/private/files");
        game.put("WINE_D3D_CONFIG","renderer=vulkan;csmt=1");
        game.put("VK_DRIVER_FILES","/private/icd.json");
        game.put("VK_ICD_FILENAMES","/private/icd.json");
        game.put("MESA_VK_WSI_DEBUG","sw");
        game.put("LD_PRELOAD","/signed/libvulkan-wrapper.so /signed/nls.so");
        game.put("WINEDLLOVERRIDES","xinput1_4=n,b;d3d12,dxgi=n,b");
        String result=KernixLaunchStackV49119.reconcile(base,game,
                R4GameRuntimeConfigV49066.VKD3D,false);
        assertEquals(base.get("HOME"),game.get("HOME"));
        assertEquals(base.get("WINEPREFIX"),game.get("WINEPREFIX"));
        assertEquals("csmt=1",game.get("WINE_D3D_CONFIG"));
        assertEquals("/private/icd.json",game.get("VK_DRIVER_FILES"));
        assertTrue(game.get("LD_PRELOAD").contains("libvulkan-wrapper"));
        assertTrue(game.get("WINEDLLOVERRIDES").contains("xinput1_4"));
        assertEquals("+err,+warn,+loaddll",game.get("WINEDEBUG"));
        assertTrue(result.contains("KERNIX_V49119_COHERENT_ENGINE=true"));
        assertTrue(result.contains("IDENTITY_REPAIRED=1"));
    }
    @Test public void wineD3dKeepsExplicitRenderer()throws Exception{
        Map<String,String> base=baseline(),game=new HashMap<>(base);
        game.put("WINE_D3D_CONFIG","renderer=vulkan");
        KernixLaunchStackV49119.reconcile(base,game,
            R4GameRuntimeConfigV49066.WINED3D,false);
        assertEquals("renderer=vulkan",game.get("WINE_D3D_CONFIG"));
    }
    @Test public void dxvkRemovesOnlyWineD3dRenderer()throws Exception{
        Map<String,String> base=baseline(),game=new HashMap<>(base);
        game.put("WINE_D3D_CONFIG","csmt=1,renderer=vulkan");
        game.put("WINEDLLOVERRIDES","xinput1_4=n,b");
        KernixLaunchStackV49119.reconcile(base,game,
                R4GameRuntimeConfigV49066.DXVK,false);
        assertEquals("csmt=1",game.get("WINE_D3D_CONFIG"));
        assertEquals("xinput1_4=n,b",game.get("WINEDLLOVERRIDES"));
    }
    @Test public void rejectsMismatchedDx12DriverClosure()throws Exception{
        Map<String,String> base=baseline(),game=new HashMap<>(base);
        game.put("VK_DRIVER_FILES","/private/icd-a.json");
        game.put("VK_ICD_FILENAMES","/private/icd-b.json");
        game.put("MESA_VK_WSI_DEBUG","sw");
        try{
            KernixLaunchStackV49119.reconcile(base,game,
                    R4GameRuntimeConfigV49066.VKD3D,false);
            fail("must reject conflicting Vulkan provider");
        }catch(java.io.IOException ok){
            assertEquals("KERNIX_DX12_MIXED_VULKAN_ICD",ok.getMessage());
        }
    }
    @Test public void failsWhenTranslationRuntimeIsNotInstalled()throws Exception{
        Map<String,String> base=baseline(),game=new HashMap<>(base);
        base.remove("HODLL64");
        try{
            KernixLaunchStackV49119.reconcile(base,game,
                R4GameRuntimeConfigV49066.WINED3D,false);
            fail("FEX pair missing");
        }catch(java.io.IOException ok){
            assertEquals("KERNIX_ENGINE_BASELINE_INCOMPLETE:HODLL64",
                ok.getMessage());
        }
    }
}
