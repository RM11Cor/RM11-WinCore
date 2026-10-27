package com.rm11.autocore.runtime;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public final class WinePrivateWsiGameBridgeV479Test {
    @Test public void approvesOnlyCompletePrivateSoftwareWsiProof() {
        String ok="RM11_V478_CHILD_EXIT=0\n"
            +"RM11_V478_WSI_OVERRIDE=sw\n"
            +"RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=0\n"
            +"RM11_V477_VK_QUEUE_PRESENT_RESULT=0\n"
            +"RM11_V477_PRESENT_STATUS=MAGENTA_FRAME_SUBMITTED_VIA_XLIB\n"
            +"RM11_V477_PROCESS_COMPLETED=0\n";
        assertTrue(WinePrivateWsiGameBridgeV479.isApprovedV478(ok));
        assertFalse(WinePrivateWsiGameBridgeV479.isApprovedV478(null));
        assertFalse(WinePrivateWsiGameBridgeV479.isApprovedV478(""));
        assertFalse(WinePrivateWsiGameBridgeV479.isApprovedV478(ok.replace(
            "RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=0",
            "RM11_V477_VK_CREATE_SWAPCHAIN_RESULT=-3")));
        assertFalse(WinePrivateWsiGameBridgeV479.isApprovedV478(ok.replace(
            "RM11_V478_CHILD_EXIT=0","RM11_V478_CHILD_EXIT=45")));
    }
}
