package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Map;

/**
 * Read-only evidence of the actual selected Wine child's graphics route.
 * A DLL on disk or an environment flag is NOT proof of DXVK execution.
 * No game/prefix modification and no global driver overrides.
 */
public final class GameGraphicsRouteAuditV49011 {
    private GameGraphicsRouteAuditV49011() {}

    private static String state(Path p) {
        try {
            return p != null && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(p) > 0 ? "PRESENT_UNVERIFIED" : "NOT_FOUND";
        } catch (Exception ignored) {
            return "UNREADABLE";
        }
    }
    private static String safeFlag(String value) {
        if (value == null || value.isEmpty()) return "UNSET";
        return "SET";
    }

    public static String snapshot(Path exe, Map<String,String> env,
                                  String privateWsi, String d3dRoute) {
        Path parent = exe == null ? null : exe.getParent();
        Path d3d11 = parent == null ? null : parent.resolve("d3d11.dll");
        Path dxgi = parent == null ? null : parent.resolve("dxgi.dll");
        String route = "NOT_VERIFIED";
        if ("ENABLED_PRIVATE_VULKAN".equals(d3dRoute)) {
            route = "WINED3D_VULKAN_REQUESTED_NOT_DXVK_PROOF";
        } else if ("ENABLED_GAME_ONLY_SW_WSI".equals(privateWsi)) {
            route = "PRIVATE_SW_WSI_REQUESTED_NOT_FRAME_PROOF";
        }
        return "RM11_V49011_AUDIT_VERSION=1\n"
                + "RM11_V49011_SELECTED_EXE_GRAPHICS_ROUTE=" + route + "\n"
                + "RM11_V49011_GAME_LOCAL_D3D11_DLL=" + state(d3d11) + "\n"
                + "RM11_V49011_GAME_LOCAL_DXGI_DLL=" + state(dxgi) + "\n"
                + "RM11_V49011_VK_DRIVER_FILES=" + safeFlag(env.get("VK_DRIVER_FILES")) + "\n"
                + "RM11_V49011_VK_ICD_FILENAMES=" + safeFlag(env.get("VK_ICD_FILENAMES")) + "\n"
                + "RM11_V49011_WINE_D3D_CONFIG=" + safeFlag(env.get("WINE_D3D_CONFIG")) + "\n"
                + "RM11_V49011_PRESENT_OBSERVED=NOT_INSTRUMENTED\n"
                + "RM11_V49011_ANDROID_FRAME_OBSERVED=NOT_PROVEN\n"
                + "RM11_V49011_NO_GAME_FILES_MODIFIED=true";
    }
}
