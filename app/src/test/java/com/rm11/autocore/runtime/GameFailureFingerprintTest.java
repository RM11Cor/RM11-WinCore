package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class GameFailureFingerprintTest {
    @Test public void separatesRelayLimitFromWineEmulatedExceptionFailure() {
        String log="x11drv: Can't open display: 127.0.0.1:2\n"
                +"RM11_V458_ANDROID_VULKAN_DLOPEN_SUCCESS\n"
                +"err:seh:NtRaiseException Exception frame is not in stack limits";
        String relay="RM11_V459_RELAY_MAX_CLIENTS=96\n"
                +"RM11_V459_RELAY_RESERVED_CLIENTS=24\n"
                +"RM11_V459_RELAY_REJECTED_CLIENTS=0\n";
        String evidence=GameFailureFingerprint.inspect(log,relay);
        assertTrue(evidence.contains("RM11_V459_X11_OPEN_FAILED=true"));
        assertTrue(evidence.contains("RM11_V459_RELAY_LIMIT_CAUSED_REJECTION=false"));
        assertTrue(evidence.contains("RM11_V459_WINE_SEH_INVALID_STACK=true"));
        assertTrue(evidence.contains("RM11_V459_ANDROID_VULKAN_LOADED=true"));
    }
    @Test public void flagsActualCapacityDropsButNotMissingMetrics() {
        assertTrue(GameFailureFingerprint.inspect("",
                "RM11_V459_RELAY_MAX_CLIENTS=96\n"
                +"RM11_V459_RELAY_RESERVED_CLIENTS=96\n"
                +"RM11_V459_RELAY_REJECTED_CLIENTS=4\n")
                .contains("RM11_V459_RELAY_LIMIT_CAUSED_REJECTION=true"));
        assertTrue(GameFailureFingerprint.inspect(null,null)
                .contains("RM11_V459_RELAY_LIMIT_CAUSED_REJECTION=false"));
    }
}
