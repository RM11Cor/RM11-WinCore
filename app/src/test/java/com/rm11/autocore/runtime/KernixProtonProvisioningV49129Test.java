package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;

public final class KernixProtonProvisioningV49129Test {
    private final String good="P11_LOADER=EXIT_0_OUTPUT_wine11\n"+
        "P11_WINESERVER=EXIT_0_OUTPUT_server11\n"+
        "P11_WINEBOOT=EXIT_0_OUTPUT_EMPTY\n"+
        "P11_FEX_X64_SMOKE=P11_X64_GUEST_EXIT47_AND_MARKER_PASS\n";
    @Test public void requireAllFourNativeSteps() {
        assertTrue(KernixProtonProvisioningV49129.qualified(good));
        assertFalse(KernixProtonProvisioningV49129.qualified(null));
        assertFalse(KernixProtonProvisioningV49129.qualified(""));
        for(String row:good.split("\\n"))
            assertFalse(KernixProtonProvisioningV49129.qualified(
                good.replace(row+"\n","")));
    }
    @Test public void neverMistakeFailedGuestForPass(){
        assertFalse(KernixProtonProvisioningV49129.qualified(
            good.replace("P11_X64_GUEST_EXIT47_AND_MARKER_PASS",
                         "P11_X64_EXIT_47_MARKER_false")));
        assertFalse(KernixProtonProvisioningV49129.qualified(
            good.replace("P11_WINESERVER=EXIT_0","P11_WINESERVER=EXIT_1")));
        assertTrue(KernixProtonProvisioningV49129.qualified(good.replace(
            "P11_WINEBOOT=EXIT_0_OUTPUT_EMPTY",
            "P11_WINEBOOT=ALREADY_COMPLETED_WITH_THIS_NATIVE_BRIDGE")));
    }
}
