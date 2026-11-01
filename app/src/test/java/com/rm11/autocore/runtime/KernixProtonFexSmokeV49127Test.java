package com.rm11.autocore.runtime;

import static org.junit.Assert.*;
import org.junit.Test;

public final class KernixProtonFexSmokeV49127Test {
    private byte[] sample(){
        byte[] b=new byte[8192];
        b[0]='M';b[1]='Z';
        b[0x3c]=(byte)0x80;
        b[0x80]='P';b[0x81]='E';
        b[0x84]=(byte)0x64;b[0x85]=(byte)0x86;
        b[0x98]=(byte)0x0b;b[0x99]=(byte)0x02;
        return b;
    }
    @Test public void recognizeOnlyAmd64Pe32Plus() {
        byte[] x=sample();
        assertTrue(KernixProtonFexSmokeV49127.isWin64Pe(x));
        x[0x85]=0x01; // PE i386 must not qualify as FEX x64.
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(x));
        x=sample();x[0x99]=0x01; // PE32 instead of PE32+.
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(x));
    }
    @Test public void rejectsMissingOrMalformedHeaders(){
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(null));
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(new byte[800]));
        byte[] b=sample();b[0x3f]=(byte)0xff;
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(b));
        b=sample();b[0x80]='X';
        assertFalse(KernixProtonFexSmokeV49127.isWin64Pe(b));
    }
}
