package com.rm11.autocore.runtime;
import java.util.concurrent.atomic.AtomicBoolean;

/** First terminating X11 pump owns connection cleanup and permit release.
 * Exactly one caller may claim a relay session, regardless of which pump
 * closes first or whether a connection failed before its Unix handshake. */
public final class RelaySessionCompletion {
    private final AtomicBoolean finished=new AtomicBoolean(false);
    public boolean claim(){return finished.compareAndSet(false,true);}
}
