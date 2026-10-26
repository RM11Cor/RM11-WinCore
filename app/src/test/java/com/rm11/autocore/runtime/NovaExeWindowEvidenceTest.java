package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

public final class NovaExeWindowEvidenceTest {
    private static String snap(int root,int visible){
        return "RM11_V410_X11_ROOT_WINDOW_QUERY_OK\\n"
                +"x11_root_children="+root+"\\n"
                +"x11_children_viewable="+visible+"\\n"
                +"x11_attribute_errors=0\\n"
                +"x11_children_capped=false\\n";
    }

    @Test public void newMappedWindowIsAnObservationNotExeAttribution(){
        String result=NovaExeWindowEvidence.compare(snap(2,1),snap(3,2));
        assertTrue(result.contains("NEW_VIEWABLE_ROOT_WINDOW_OBSERVED"));
        assertTrue(result.contains("RM11_V436_WINDOW_OWNER_NOT_DETERMINED=true"));
    }

    @Test public void noIncreaseIsNotIncorrectlyCalledFailure(){
        String result=NovaExeWindowEvidence.compare(snap(3,2),snap(3,2));
        assertTrue(result.contains("NO_VIEWABLE_ROOT_WINDOW_INCREASE"));
        assertTrue(result.contains("GAME_COMPATIBILITY_NOT_VERIFIED=true"));
    }

    @Test public void unreachableOrIncompleteAuditIsIndeterminate(){
        assertTrue(NovaExeWindowEvidence.compare("RM11_V410_X11_WINDOW_QUERY_FAILED=IOException",snap(3,1))
                .contains("INDETERMINATE_X11_AUDIT"));
        assertTrue(NovaExeWindowEvidence.compare(snap(1,1),
                snap(2,2).replace("x11_attribute_errors=0","x11_attribute_errors=1"))
                .contains("INDETERMINATE_X11_AUDIT"));
        assertTrue(NovaExeWindowEvidence.compare(snap(1,1),
                snap(2,2).replace("x11_children_capped=false","x11_children_capped=true"))
                .contains("INDETERMINATE_X11_AUDIT"));
    }
}
