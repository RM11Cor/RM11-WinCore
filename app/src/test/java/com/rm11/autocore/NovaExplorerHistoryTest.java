package com.rm11.autocore;

import org.junit.Test;
import java.io.File;
import static org.junit.Assert.*;

public final class NovaExplorerHistoryTest {
    @Test public void backAndForwardRestoreFoldersWithoutLoops(){
        NovaExplorerHistory h=new NovaExplorerHistory();
        File games=new File("/games");
        File inside=new File("/games/GTA V");
        h.reset(null);
        assertFalse(h.canBack());
        assertTrue(h.visit(games));
        assertTrue(h.visit(inside));
        assertTrue(h.back());
        assertEquals(games,h.current());
        assertTrue(h.back());
        assertNull(h.current()); // This PC
        assertFalse(h.canBack());
        assertTrue(h.forward());
        assertEquals(games,h.current());
        assertTrue(h.forward());
        assertEquals(inside,h.current());
        assertFalse(h.canForward());
    }
    @Test public void newNavigationInvalidatesForwardButNotBack(){
        NovaExplorerHistory h=new NovaExplorerHistory();
        File c=new File("/C");
        File d=new File("/D");
        h.reset(null);
        h.visit(c);
        h.back();
        assertTrue(h.canForward());
        h.visit(d);
        assertFalse(h.canForward());
        assertTrue(h.back());
        assertNull(h.current());
    }
    @Test public void duplicateNavigationNeverAddsHistory(){
        NovaExplorerHistory h=new NovaExplorerHistory();
        File desktop=new File("/Desktop");
        h.reset(desktop);
        assertFalse(h.visit(desktop));
        assertFalse(h.canBack());
        assertFalse(h.back());
    }
    @Test public void navigationCapsHistoryAndResetClearsState(){
        NovaExplorerHistory h=new NovaExplorerHistory();
        h.reset(null);
        for(int i=0;i<100;i++)h.visit(new File("/folder"+i));
        int back=0;
        while(h.back())back++;
        assertEquals(64,back);
        h.reset(new File("/fresh"));
        assertFalse(h.canForward());
        assertFalse(h.canBack());
        assertEquals(new File("/fresh"),h.current());
    }
}
