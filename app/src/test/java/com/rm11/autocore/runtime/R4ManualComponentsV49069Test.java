package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
public class R4ManualComponentsV49069Test {
    @Test public void explicitPerCategoryDefaults(){
        assertEquals("WINE_BUNDLED",R4ManualComponentsV49069.defaultFor("WINE"));
        assertEquals("FEX_BUNDLED",R4ManualComponentsV49069.defaultFor("FEX"));
        assertEquals("AUTO",R4ManualComponentsV49069.defaultFor("GRAPHICS"));
        assertEquals("VULKAN_AUTO",R4ManualComponentsV49069.defaultFor("VULKAN"));
        assertEquals("DIRECT",R4ManualComponentsV49069.defaultFor("LAUNCH"));
    }
}
