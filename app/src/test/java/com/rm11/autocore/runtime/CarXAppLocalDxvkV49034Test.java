package com.rm11.autocore.runtime;

import org.junit.Test;
import java.nio.file.Paths;
import static org.junit.Assert.*;

public final class CarXAppLocalDxvkV49034Test {
    @Test public void selectsOnlyExactUserApprovedCarxGameExeName(){
        assertTrue(CarXAppLocalDxvkV49034.exactGame(Paths.get("/games/CarX Street/CarX Street.exe")));
        assertTrue(CarXAppLocalDxvkV49034.exactGame(Paths.get("/games/CarX Street/CARX STREET.EXE")));
        assertFalse(CarXAppLocalDxvkV49034.exactGame(Paths.get("/games/CarX Street/CarX Street Launcher.exe")));
        assertFalse(CarXAppLocalDxvkV49034.exactGame(Paths.get("/games/CarX Street/CarX Street.exe.bak")));
        assertFalse(CarXAppLocalDxvkV49034.exactGame(Paths.get("/games/GTA V/GTA5.exe")));
        assertFalse(CarXAppLocalDxvkV49034.exactGame(null));
    }
}
