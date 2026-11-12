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
    @Test public void actualP29GraphReconvergesAtTakenPath() {
        JumpJoin.GraphResult r=JumpJoin.classifyGraph(
            3221716,3200185,3208198,3221716,186682112);
        assertEquals("RECONVERGENCE_AT_TAKEN_BRANCH",r.status);
        assertEquals(3221716,r.joinRva);
        assertFalse(r.cycleDetected);
    }
    @Test public void mutualJumpsAreAnActualCycle() {
        JumpJoin.GraphResult r=JumpJoin.classifyGraph(
            0x1000,0x2000,0x2000,0x1000,0x10000);
        assertEquals("STATIC_CYCLE_DETECTED",r.status);
        assertTrue(r.cycleDetected);
    }
    @Test public void sameNextHopIsConvergence() {
        JumpJoin.GraphResult r=JumpJoin.classifyGraph(
            0x1000,0x2000,0x3000,0x3000,0x10000);
        assertEquals("RECONVERGENCE_AT_SHARED_NEXT_TARGET",r.status);
        assertEquals(0x3000,r.joinRva);
    }
    @Test public void selfJumpIsLoopNotConvergence() {
        assertTrue(JumpJoin.classifyGraph(0x1000,0x2000,0x1000,0x3000,0x10000).cycleDetected);
        assertTrue(JumpJoin.classifyGraph(0x1000,0x2000,0x3000,0x2000,0x10000).cycleDetected);
    }
    @Test public void unresolvedCannotImplyJoin() {
        JumpJoin.GraphResult r=JumpJoin.classifyGraph(
            0x1000,0x2000,-1,0x3000,0x10000);
        assertEquals("SECOND_HOP_UNRESOLVED",r.status);
        assertEquals(-1,r.joinRva);
    }
    @Test public void distinctSecondHopsRemainSeparate() {
        assertEquals("DISTINCT_SECOND_HOP_TARGETS",
            JumpJoin.classifyGraph(0x1000,0x2000,0x3000,0x4000,0x10000).status);
    }
    @Test public void crossLinkToOtherBranchWorksBothWays() {
        JumpJoin.GraphResult r=JumpJoin.classifyGraph(
            0x1000,0x2000,0x2000,0x3000,0x10000);
        assertEquals("RECONVERGENCE_AT_NOT_TAKEN_BRANCH",r.status);
        assertEquals(0x2000,r.joinRva);
    }
}
