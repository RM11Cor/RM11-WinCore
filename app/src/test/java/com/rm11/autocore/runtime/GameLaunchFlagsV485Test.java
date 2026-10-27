package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Collections;

public final class GameLaunchFlagsV485Test {
    @Test public void usesOfficialCarxDx11LaunchOptionOnlyForExactName() {
        assertEquals(Collections.singletonList("-force-d3d11"),
                GameLaunchFlagsV485.argumentsFor("CarX Street Launcher.exe"));
        assertEquals(Collections.emptyList(),
                GameLaunchFlagsV485.argumentsFor("CarX Street.exe"));
        assertEquals(Collections.emptyList(),
                GameLaunchFlagsV485.argumentsFor("Hollow Knight Silksong.exe"));
        assertEquals(Collections.emptyList(),
                GameLaunchFlagsV485.argumentsFor("CarX Street Launcher.exe.bak"));
        assertEquals(Collections.emptyList(),
                GameLaunchFlagsV485.argumentsFor(null));
    }
}
