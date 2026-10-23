package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Evidence only: Wine GUI driver presence does NOT prove Android display integration. */
public final class WineGraphicsReadiness {
    private WineGraphicsReadiness() {}

    public static String report(RuntimeLayout p, Map<String,String> env) {
        Path windows=p.wineDllRoot.resolve("aarch64-windows");
        Path unix=p.wineDllRoot.resolve("aarch64-unix");
        boolean x11Pe=Files.isRegularFile(windows.resolve("winex11.drv"));
        boolean waylandPe=Files.isRegularFile(windows.resolve("winewayland.drv"));
        boolean x11Unix=Files.isRegularFile(unix.resolve("winex11.so"));
        boolean waylandUnix=Files.isRegularFile(unix.resolve("winewayland.so"));
        boolean vulkan=Files.isRegularFile(unix.resolve("winevulkan.so"));
        boolean x11Endpoint=existsEnv(env,"DISPLAY");
        boolean waylandEndpoint=existsEnv(env,"WAYLAND_DISPLAY")
                && existsEnv(env,"XDG_RUNTIME_DIR");
        return new StringBuilder("RM11_WIN32_GUI_READINESS_V271\n")
                .append("PE winex11.drv: ").append(yn(x11Pe)).append('\n')
                .append("Native winex11.so: ").append(yn(x11Unix)).append('\n')
                .append("PE winewayland.drv: ").append(yn(waylandPe)).append('\n')
                .append("Native winewayland.so: ").append(yn(waylandUnix)).append('\n')
                .append("Native winevulkan.so: ").append(yn(vulkan)).append('\n')
                .append("DISPLAY configured: ").append(yn(x11Endpoint)).append('\n')
                .append("WAYLAND_DISPLAY and XDG_RUNTIME_DIR configured: ").append(yn(waylandEndpoint)).append('\n')
                .append("Wine X11/Wayland server handshake tested: NO\n")
                .append("Android Surface connected to Wine desktop: NOT VERIFIED\n")
                .append("DXVK and VKD3D game rendering: NOT VERIFIED\n")
                .append("Windows GUI readiness: ")
                .append((x11Pe && x11Unix && x11Endpoint)
                        || (waylandPe && waylandUnix && waylandEndpoint)
                        ? "DRIVER_AND_ENDPOINT_PRESENT_UNVERIFIED"
                        : "DISPLAY_BACKEND_NOT_YET_READY")
                .append('\n').toString();
    }

    private static boolean existsEnv(Map<String,String> env,String key) {
        String value=env==null?null:env.get(key);
        return value!=null && !value.trim().isEmpty();
    }

    private static String yn(boolean yes) { return yes ? "PRESENT" : "MISSING"; }
}
