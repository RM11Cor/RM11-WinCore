package com.rm11.autocore.runtime;

/** Deterministic policy for v484 read-only diagnostics and tightly gated
 * one-shot v483 X11 MapWindow. No depends-on-explorer-alive condition:
 * device v483 showed nogui can remain alive while all X11 children are unmapped.
 */
public final class GameWindowRecoveryGateV484 {
    private GameWindowRecoveryGateV484(){}
    public static boolean inventory(long elapsed,long previousBand,
            boolean gameAlive,boolean x11Ready) {
        return elapsed>=16000 && gameAlive && x11Ready
                && elapsed/20000!=previousBand;
    }
    public static boolean recovery(long elapsed,int consecutiveEmptyX11,
            boolean x11Ready,boolean gameAlive,boolean alreadyTried,
            int children,int unmapped) {
        return elapsed>=24000 && consecutiveEmptyX11>=2
                && x11Ready && gameAlive && !alreadyTried
                && children>0 && unmapped>0;
    }
    public static int nonnegativeCount(String audit,String key) {
        if(audit==null || key==null)return -1;
        int p=audit.indexOf(key);
        if(p<0)return -1;
        p+=key.length();
        int end=p;
        while(end<audit.length() && Character.isDigit(audit.charAt(end)))end++;
        if(end==p)return -1;
        try{return Integer.parseInt(audit.substring(p,end));}
        catch(NumberFormatException bad){return -1;}
    }
}
