package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import org.junit.Test;

public final class X11HiddenWindowRecoveryPolicyV483Test {
    @Test public void onlyOneUnmappedLargeOrdinaryWindowCanQualify() {
        assertTrue(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,0,false,2688,1216,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,2,false,2688,1216,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,1,false,2688,1216,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,0,true,2688,1216,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            2,0,false,2688,1216,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,0,false,320,240,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,0,false,6000,4000,2688,1216));
        assertFalse(X11HiddenWindowRecoveryPolicyV483.isCandidate(
            1,0,false,2688,1216,0,0));
    }
}
