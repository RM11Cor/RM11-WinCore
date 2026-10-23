package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Map;

public final class WineCpuRegistryBootstrapTest {
    private static final String DATA =
        "RM11_CPU_ID_STATUS=MEASURED_EL0_HWCAP_CPUID\n" +
        "CP 4030=1122334455667788\nCP 4020=1234000000000000\nCP 4021=0000000000000000\n" +
        "CP 4031=0000000000000001\nCP 4038=0000000000000002\nCP 403A=0000000000000003\n" +
        "CP 4024=0000000000000000\nCP 4039=0000000000000004\nCP 4032=0000000000000005\n" +
        "CP 5801=0000000000000006\nCP 4000=0000000000000007\n";

    @Test public void measuresAllRequiredRecordsAndRendersCorrectQwordBytes() {
        Map<String,Long> values = WineCpuRegistryBootstrap.parseMeasuredValues(DATA);
        assertEquals(11, values.size());
        String result=WineCpuRegistryBootstrap.renderFirstCpuKey(values, 123L);
        assertTrue(result.contains("[Hardware\\Description\\System\\CentralProcessor\\0] 123\n"));
        assertTrue(result.contains("\"CP 4030\"=hex(b):88,77,66,55,44,33,22,11"));
    }
    @Test public void insertsOnlyIntoRecognizedWineRegistry() {
        String old="WINE REGISTRY Version 2\n;; All keys relative to REGISTRY\\Machine\n\n#arch=win64\n\n[Software\\Classes] 12\n@=\"x\"\n";
        String block=WineCpuRegistryBootstrap.renderFirstCpuKey(
                WineCpuRegistryBootstrap.parseMeasuredValues(DATA),123);
        String updated=WineCpuRegistryBootstrap.insertOnlyIfMissing(old,block);
        assertTrue(updated.indexOf("[Hardware")<updated.indexOf("[Software"));
        assertTrue(updated.contains(old.substring(old.indexOf("[Software"))));
        try {
            WineCpuRegistryBootstrap.insertOnlyIfMissing(updated,block);
            fail("Must not overwrite pre-existing CPU record");
        } catch (IllegalStateException expected) { }
    }
    @Test public void refusesUnmeasuredAndMissingCPIDs() {
        try { WineCpuRegistryBootstrap.parseMeasuredValues(DATA.replace("MEASURED_EL0_HWCAP_CPUID","UNSUPPORTED")); fail(); }
        catch (IllegalArgumentException expected) { }
        try { WineCpuRegistryBootstrap.parseMeasuredValues(DATA.replace("CP 403A=0000000000000003\n","")); fail(); }
        catch (IllegalArgumentException expected) { }
        try { WineCpuRegistryBootstrap.parseMeasuredValues(DATA.replace("CP 4000=0000000000000007","CP 4000=0000000000000000")); fail(); }
        catch (IllegalArgumentException expected) { }
    }
}
