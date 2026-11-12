package com.rm11cor.carxstreet.portlab;

import java.util.Locale;

/** Owner-local bounded source executable intervals between observed Win64
 * RUNTIME_FUNCTION fragments. An in-between RVA may hold unrelated code or
 * alignment bytes: this reader never calls a gap an original gameplay method.
 */
public final class Win64InterRegionGapPolicy {
    private Win64InterRegionGapPolicy() {}
    public static final int MAX_GAP_BYTES=4096;
    public static final int MAX_TOTAL_GAP_BYTES=2*1024*1024;
    public static final int MAX_GAPS=1024;

    public static int checkedLength(long begin,long end) {
        if(begin<=0 || end<=begin || end>0xffffffffL)
            throw new IllegalArgumentException("invalid original PE gap RVA bounds");
        long size=end-begin;
        if(size>MAX_GAP_BYTES)
            throw new IllegalArgumentException("source gap exceeds 4096 bytes");
        return (int)size;
    }

    public static String memberName(long begin,long end) {
        checkedLength(begin,end);
        return String.format(Locale.ROOT,"gaps/rva_%08x.bin",begin);
    }

    public static boolean canInclude(int alreadyExported,long totalBytes,int add) {
        return alreadyExported>=0 && alreadyExported<MAX_GAPS &&
                totalBytes>=0 && add>0 && add<=MAX_GAP_BYTES &&
                totalBytes<=MAX_TOTAL_GAP_BYTES-add;
    }
}
