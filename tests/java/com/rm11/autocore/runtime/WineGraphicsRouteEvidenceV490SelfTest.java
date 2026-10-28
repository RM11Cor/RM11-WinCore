package com.rm11.autocore.runtime;

/** JDK-only executable guard for Wine's actual +loaddll line format. */
public final class WineGraphicsRouteEvidenceV490SelfTest {
    private static void yes(boolean condition,String reason) {
        if(!condition)throw new AssertionError(reason);
    }
    private static void checkContains(String report,String key,String expected) {
        yes(report.contains(key+"="+expected),"expected "+key+"="+expected+"\n"+report);
    }
    public static void main(String[] args) {
        WineGraphicsRouteEvidenceV490 e=new WineGraphicsRouteEvidenceV490();
        checkContains(e.snapshot(),"RM11_V490_DXVK_MODULE_STATUS","DXVK_MODULE_LOAD_NOT_PROVEN");
        e.accept("007f:trace:loaddll:build_module Loaded L\"C:\\windows\\system32\\d3d11.dll\" at 000000: native\n");
        e.accept("0080:trace:loaddll:build_module Loaded L\"C:\\windows\\system32\\dxgi.dll\" at 000000: native\n");
        checkContains(e.snapshot(),"RM11_V490_DXVK_MODULE_STATUS",
                "NATIVE_D3D11_DXGI_LOADED_DXVK_UNCONFIRMED");
        checkContains(e.snapshot(),"RM11_V490_EXPLICIT_DXVK_INIT_LOG_OBSERVED","false");
        e.accept("info:  DXVK: v2.7.0\n");
        checkContains(e.snapshot(),"RM11_V490_EXPLICIT_DXVK_INIT_LOG_OBSERVED","true");
        checkContains(e.snapshot(),"RM11_V490_DXVK_MODULE_STATUS",
                "DXVK_MODULE_INIT_SIGNAL_ONLY_NO_FRAME_PROOF");
        e.acceptX11("RM11_V410_X11_ROOT_WINDOW_QUERY_OK\n"+
                "x11_children_viewable=2\nx11_root_children=2\n");
        checkContains(e.snapshot(),"RM11_V490_X11_VIEWABLE_ROOT_CHILD_OBSERVED","true");
        checkContains(e.snapshot(),"RM11_V490_X11_WINDOW_BELONGS_TO_SELECTED_GAME","false");
        checkContains(e.snapshot(),"RM11_V490_ANDROID_GAME_FRAME_VISIBLE","NOT_PROVEN");
        checkContains(e.snapshot(),"RM11_V490_PRIVATE_TURNIP_IN_WINE_PROCESS","NOT_PROVEN");

        WineGraphicsRouteEvidenceV490 builtin=new WineGraphicsRouteEvidenceV490();
        builtin.accept("trace:loaddll:build_module Loaded L\"x:\\d3d11.dll\" at 0x0: builtin\n");
        checkContains(builtin.snapshot(),"RM11_V490_D3D11_NATIVE_MODULE_OBSERVED","false");
        checkContains(builtin.snapshot(),"RM11_V490_D3D11_BUILTIN_MODULE_OBSERVED","true");
        checkContains(builtin.snapshot(),"RM11_V490_DXVK_MODULE_STATUS",
                "WINE_BUILTIN_D3D_MODULE_OBSERVED");
        builtin.acceptX11("x11_children_viewable=12\n");
        checkContains(builtin.snapshot(),"RM11_V490_X11_ROOT_QUERY_OK","false");

        WineGraphicsRouteEvidenceV490 fragmented=new WineGraphicsRouteEvidenceV490();
        fragmented.accept("trace:loaddll:build_module Loaded L\"C:\\windows\\system32\\dx");
        fragmented.accept("gi.dll\" at 0x0: native\n");
        checkContains(fragmented.snapshot(),"RM11_V490_DXGI_NATIVE_MODULE_OBSERVED","true");
        fragmented.accept("warn: winevulkan vkCreateSwapchainKHR returned VK_ERROR_EXTENSION_NOT_PRESENT\n");
        checkContains(fragmented.snapshot(),"RM11_V490_VULKAN_SURFACE_OR_INIT_ERROR_OBSERVED","true");

        WineGraphicsRouteEvidenceV490 noFalseNative=new WineGraphicsRouteEvidenceV490();
        noFalseNative.accept("trace:loaddll:build_module Loaded L\"x:\\native\\d3d11.dll\" at 0x0: builtin\n");
        checkContains(noFalseNative.snapshot(),"RM11_V490_D3D11_NATIVE_MODULE_OBSERVED","false");
        checkContains(noFalseNative.snapshot(),"RM11_V490_D3D11_BUILTIN_MODULE_OBSERVED","true");

        WineGraphicsRouteEvidenceV490 bounded=new WineGraphicsRouteEvidenceV490();
        bounded.accept("A".repeat(16000)+"\n");
        checkContains(bounded.snapshot(),"RM11_V490_OVERSIZED_LINES_TRUNCATED","true");
        System.out.println("RM11_V490_REAL_GAME_TRACE_AUDIT_JDK_TESTS_PASS");
    }
}
