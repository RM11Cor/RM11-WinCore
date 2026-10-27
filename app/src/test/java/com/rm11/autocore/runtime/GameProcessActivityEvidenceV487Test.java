package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class GameProcessActivityEvidenceV487Test {
    @Test public void parsesLinuxStatIndicesAfterExecutableNameWithSpaces(){
        // fields 3..20: state, ppid, pgrp, session, tty, tpgid, flags,
        // minflt, cminflt, majflt, cmajflt, utime, stime, cutime, cstime,
        // priority, nice, num_threads
        String stat="42 (CarX Street Launcher.exe) S 1 2 3 4 5 6 7 8 9 10 120 34 15 16 17 18 4 0 0";
        GameProcessActivityEvidenceV487.Stat x=GameProcessActivityEvidenceV487.parseStat(stat);
        assertEquals('S',x.state);
        assertEquals(120,x.userTicks);
        assertEquals(34,x.systemTicks);
        assertEquals(154,x.cpuTicks());
        assertEquals(4,x.threads);
        assertEquals(0,GameProcessActivityEvidenceV487.childCount("  "));
        assertEquals(3,GameProcessActivityEvidenceV487.childCount(" 1  21 305 \n"));
    }
    @Test public void absentProcfsNeverPretendsToConfirmStartup(){
        String r=GameProcessActivityEvidenceV487.create().sample(-1,20000,true);
        assertTrue(r.contains("RM11_V487_PROCFS=PID_NOT_OBSERVABLE"));
        assertTrue(r.contains("RM11_V487_SELECTED_PE_PROGRESS=UNVERIFIED"));
    }
}
