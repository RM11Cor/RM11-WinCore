package com.rm11.autocore;

/**
 * Evidence-gated fallback for a real Wine desktop that starts without any
 * visible X11 top-level window. Never infer failure from black pixels alone:
 * they can also mean the Android/X11 renderer is disconnected.
 */
public final class WineShellStartupPolicy {
    private WineShellStartupPolicy() {}

    public static boolean shouldLaunchFileManager(String x11Evidence,
            long sinceExplorerMs, int consecutiveEmptySamples, boolean attempted) {
        return !attempted
                && sinceExplorerMs >= 8000L
                && consecutiveEmptySamples >= 2
                && x11Evidence != null
                && x11Evidence.contains("RM11_V410_X11_ROOT_WINDOW_QUERY_OK")
                && x11Evidence.contains("x11_children_viewable=0\n")
                && x11Evidence.contains("x11_attribute_errors=0\n");
    }
}
