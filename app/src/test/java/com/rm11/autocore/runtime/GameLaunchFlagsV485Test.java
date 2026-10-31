package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Collections;
public final class GameLaunchFlagsV485Test {
    @Test public void noGameNameChangesLaunchFlags(){
        for(String name:new String[]{"CarX Street.exe","GTA5.exe",
                "Hollow Knight Silksong.exe","CarX Street Launcher.exe"})
            assertEquals(Collections.emptyList(),GameLaunchFlagsV485.argumentsFor(name));
        assertEquals(Collections.emptyList(),GameLaunchFlagsV485.argumentsFor(null));
    }
}
