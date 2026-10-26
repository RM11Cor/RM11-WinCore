package com.rm11.autocore.runtime;
import org.junit.Test;
import static org.junit.Assert.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class RelaySessionCompletionTest {
    @Test public void onlyOnePumpCanReleaseX11SlotUnderRace() throws Exception {
        RelaySessionCompletion completion=new RelaySessionCompletion();
        AtomicInteger releases=new AtomicInteger(0);
        Thread[] readers=new Thread[32];
        for(int i=0;i<readers.length;i++){
            readers[i]=new Thread(()->{
                if(completion.claim())releases.incrementAndGet();
            });
        }
        for(Thread t:readers)t.start();
        for(Thread t:readers)t.join();
        assertEquals(1,releases.get());
        assertFalse(completion.claim());
    }
}
