package com.fh5.port;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import static org.junit.Assert.*;

public final class DllDependencyPlannerTest {
    @Test public void separatesApiSetsAndLocalFiles() {
        DllDependencyPlanner.Report r=DllDependencyPlanner.assess(
            Arrays.asList("steam_api64.dll","KERNEL32.DLL",
                "api-ms-win-crt-runtime-l1-1-0.dll","d3d12.dll","bink2w64.dll"),
            new HashSet<>(Arrays.asList("STEAM_API64.DLL","bink2w64.dll")),
            true);
        assertEquals(5,r.entries.size());
        assertEquals(2,r.localCount);
        assertEquals(3,r.notLocalCount);
        assertEquals(0,r.notCheckedCount);
        assertEquals(1,r.apiSetCount);
        assertEquals("GAME_PLATFORM_SERVICES",r.entries.get(0).group);
        assertEquals("WINDOWS_SYSTEM_API",r.entries.get(1).group);
        assertEquals("WINDOWS_API_SET_CONTRACT",r.entries.get(2).group);
        assertEquals("DX12_GRAPHICS_BRIDGE_REQUIRED",r.entries.get(3).group);
        assertEquals(DllDependencyPlanner.LOCAL_PRESENT,r.entries.get(4).localStatus);
        assertEquals(DllDependencyPlanner.NOT_LOCAL,r.entries.get(3).localStatus);
    }
    @Test public void noPermissionNeverReportsDllsMissing() {
        DllDependencyPlanner.Report r=DllDependencyPlanner.assess(
            Arrays.asList("kernel32.dll","steam_api64.dll"),
            Collections.emptySet(),false);
        assertEquals(0,r.localCount);
        assertEquals(0,r.notLocalCount);
        assertEquals(2,r.notCheckedCount);
        assertEquals(DllDependencyPlanner.NOT_CHECKED,r.entries.get(1).localStatus);
    }
    @Test public void rejectsPathLikeNames() {
        try {
            DllDependencyPlanner.assess(Arrays.asList("../steam_api64.dll"),
                Collections.emptySet(),true);
            fail("path must not be accepted");
        } catch(IllegalArgumentException expected){}
    }
    @Test public void groupLabelsAreNotRuntimeProof() {
        assertEquals("MSVC_RUNTIME_DEPENDENCY",DllDependencyPlanner.group("vcruntime140.dll"));
        assertEquals("GAME_VENDOR_OR_OTHER",DllDependencyPlanner.group("amd_ags_x64.dll"));
    }
}
