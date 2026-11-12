package com.rm11cor.carxstreet.portlab;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;

/**
 * Bounded original GameAssembly PE .pdata sampling (NO source bytes copied).
 *
 * The prior global method-rank reservoir selected 256 regions but repeated
 * the SAME original Win64 unwind RVA for many regions: the owner's v1.0
 * 256-region ZIP had only 149 distinct unwind RVAs, including one reused
 * by 24 regions. A repeated xdata RVA can be ordinary metadata sharing;
 * it does not itself imply a chained method or duplicated machine code.
 *
 * This selector picks a stable, input-order-independent distribution over
 * distinct unwind RVAs first, then one representative executable range
 * per selected unwind RVA. Exactly MAX samples and O(MAX) memory.
 *
 * It does NOT prove that any selected range is an IL2CPP gameplay method;
 * callers must still decode xdata + CFG, reference-run and prove AArch64.
 */
public final class Win64UnwindDiverseSampler {
    public static final class Range {
        public final long begin,end,unwind;
        public final long groupRank,methodRank;
        Range(long begin,long end,long unwind,long groupRank,long methodRank) {
            this.begin=begin;
            this.end=end;
            this.unwind=unwind;
            this.groupRank=groupRank;
            this.methodRank=methodRank;
        }
        public long bytes() {return end-begin;}
    }

    private static final Comparator<Range> WORST_FIRST=(a,b)-> {
        int c=Long.compareUnsigned(b.groupRank,a.groupRank);
        if(c!=0)return c;
        return Long.compareUnsigned(b.unwind,a.unwind);
    };

    private final int limit;
    private final HashMap<Long,Range> byUnwind=new HashMap<>();
    private final TreeSet<Range> ranked=new TreeSet<>(WORST_FIRST);
    private long acceptedRanges=0;

    public Win64UnwindDiverseSampler(int maxSamples) {
        if(maxSamples<1||maxSamples>4096)
            throw new IllegalArgumentException("sampler capacity out of range");
        limit=maxSamples;
    }

    private static long mix64(long input) {
        long z=input+0x9e3779b97f4a7c15L;
        z=(z^(z>>>30))*0xbf58476d1ce4e5b9L;
        z=(z^(z>>>27))*0x94d049bb133111ebL;
        return z^(z>>>31);
    }

    public void accept(long begin,long end,long unwind) {
        if(begin<=0||end<=begin||end>0xffffffffL ||
           unwind<=0||unwind>0xffffffffL)
            throw new IllegalArgumentException("original PE RVA/length out of range");
        acceptedRanges++;
        final long group=mix64(unwind^0x4752305f554e5744L);
        final long method=mix64((begin<<32)^end^unwind);
        Range old=byUnwind.get(unwind);
        if(old!=null) {
            // Same xdata metadata, choose best deterministic region.
            if(Long.compareUnsigned(method,old.methodRank)<0 ||
                (method==old.methodRank && begin<old.begin)) {
                Range replacement=new Range(begin,end,unwind,group,method);
                ranked.remove(old);
                ranked.add(replacement);
                byUnwind.put(unwind,replacement);
            }
            return;
        }
        Range candidate=new Range(begin,end,unwind,group,method);
        if(byUnwind.size()==limit) {
            Range worst=ranked.first();
            if(WORST_FIRST.compare(candidate,worst)<=0)return;
            ranked.pollFirst();
            byUnwind.remove(worst.unwind);
        }
        byUnwind.put(unwind,candidate);
        ranked.add(candidate);
    }

    public int distinctUnwindRvasSelected() {return byUnwind.size();}
    public long totalValidOriginalPdataRegionsSeen() {return acceptedRanges;}

    public List<Range> chosenByBeginRva() {
        ArrayList<Range> out=new ArrayList<>(byUnwind.values());
        out.sort(Comparator.comparingLong(a->a.begin));
        return out;
    }
}
