package com.fh5.port;

import org.junit.Test;
import static org.junit.Assert.*;

public final class JumpJoinTest {
    @Test public void joinedBranchesAreRecognizedWithoutExecution() {
        assertEquals("SAME_IMMEDIATE_JMP_DESTINATION",JumpJoin.classify(0x9000,0x9000,0x20000));
    }
    @Test public void distinctBranchesRemainDistinct() {
        assertEquals("DISTINCT_IMMEDIATE_JMP_DESTINATIONS",JumpJoin.classify(0x9000,0x9200,0x20000));
    }
    @Test public void unresolvedOrOutOfImageIsNotConvergence() {
        assertEquals("ONE_OR_BOTH_UNRESOLVED",JumpJoin.classify(-1,0x9000,0x20000));
        assertEquals("ONE_OR_BOTH_UNRESOLVED",JumpJoin.classify(0x30000,0x9000,0x20000));
        assertEquals("ONE_OR_BOTH_UNRESOLVED",JumpJoin.classify(0,0,0x20000));
        assertEquals("ONE_OR_BOTH_UNRESOLVED",JumpJoin.classify(0x9000,0x9000,0));
    }
    @Test public void cyclesAndCrossLinksGetRecognized() {
        assertTrue(JumpJoin.previouslyVisited(0x7000,0x7000,0x9000,0x4000));
        assertTrue(JumpJoin.previouslyVisited(0x9000,0x7000,0x9000,0x4000));
        assertTrue(JumpJoin.previouslyVisited(0x4000,0x7000,0x9000,0x4000));
        assertFalse(JumpJoin.previouslyVisited(0xA000,0x7000,0x9000,0x4000));
    }
}
