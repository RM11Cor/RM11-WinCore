package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;

public final class PostJoinBranchTest {
    @Test public void confirmsRealReportTargetButDoesNotInventFallthrough() {
        assertEquals("SAFE_DIRECT_IN_IMAGE_TARGET",
            PostJoinBranch.classifyTarget(8539278,186682112,8361984,-1));
        assertEquals("ONE_OR_BOTH_SUCCESSORS_UNRESOLVED",
            PostJoinBranch.classifyPair(8539278,-1,186682112));
    }
    @Test public void twoKnownPathsRemainStatic() {
        assertEquals("TWO_DISTINCT_STATIC_SUCCESSORS",
            PostJoinBranch.classifyPair(8539278,8362100,186682112));
        assertEquals("SAME_DIRECT_SUCCESSOR",
            PostJoinBranch.classifyPair(8539278,8539278,186682112));
    }
    @Test public void refusesBadAddressesAndCycles() {
        assertEquals("DIRECT_TARGET_UNRESOLVED_OR_OUT_OF_IMAGE",
            PostJoinBranch.classifyTarget(186682112,186682112,8361984,-1));
        assertEquals("DIRECT_TARGET_UNRESOLVED_OR_OUT_OF_IMAGE",
            PostJoinBranch.classifyTarget(-1,186682112,8361984,-1));
        assertEquals("STATIC_SELF_LOOP",
            PostJoinBranch.classifyTarget(8361984,186682112,8361984,-1));
        assertEquals("DUPLICATE_OTHER_SUCCESSOR",
            PostJoinBranch.classifyTarget(8539278,186682112,8361984,8539278));
    }
    @Test public void hardBudgetDoesNotExpandWithArchiveSize() {
        assertEquals(2,PostJoinBranch.MAX_SUCCESSOR_PROBES);
        assertEquals(128,PostJoinBranch.SAMPLE_BYTES_PER_SUCCESSOR);
    }
}
