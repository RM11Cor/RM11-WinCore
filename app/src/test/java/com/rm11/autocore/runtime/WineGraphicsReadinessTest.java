package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;

public final class WineGraphicsReadinessTest {
    @Test public void driversWithoutDisplayEndpointCannotBeCalledReady() throws Exception {
        Path tmp=Files.createTempDirectory("rm11-gui-");
        Path files=tmp.resolve("files"),libs=tmp.resolve("native");
        Files.createDirectories(files);
        Files.createDirectories(libs);
        RuntimeLayout layout=new RuntimeLayout(files,libs);
        Path win=layout.wineDllRoot.resolve("aarch64-windows");
        Path unix=layout.wineDllRoot.resolve("aarch64-unix");
        Files.createDirectories(win);
        Files.createDirectories(unix);
        Files.write(win.resolve("winewayland.drv"),new byte[]{1});
        Files.write(unix.resolve("winewayland.so"),new byte[]{1});
        Files.write(unix.resolve("winevulkan.so"),new byte[]{1});
        String report=WineGraphicsReadiness.report(layout,new HashMap<>());
        assertTrue(report.contains("DISPLAY_BACKEND_NOT_YET_READY"));
        assertTrue(report.contains("Android Surface connected to Wine desktop: NOT VERIFIED"));
        assertTrue(report.contains("Native winevulkan.so: PRESENT"));
        Map<String,String> enabled=new HashMap<>();
        enabled.put("WAYLAND_DISPLAY","wayland-0");
        enabled.put("XDG_RUNTIME_DIR","/tmp/runtime");
        String next=WineGraphicsReadiness.report(layout,enabled);
        assertTrue(next.contains("DRIVER_AND_ENDPOINT_PRESENT_UNVERIFIED"));
        assertTrue(next.contains("Wine X11/Wayland server handshake tested: NO"));
    }
}
