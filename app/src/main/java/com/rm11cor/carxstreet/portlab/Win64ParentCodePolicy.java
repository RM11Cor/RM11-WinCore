package com.rm11cor.carxstreet.portlab;

/**
 * Strict owner-local PE .pdata CHAININFO referenced code extraction bounds.
 *
 * The parent's [BeginAddress,EndAddress) is another original Win64
 * RUNTIME_FUNCTION region, NOT proof of a complete or independently
 * callable original Unity IL2CPP gameplay method.
 */
public final class Win64ParentCodePolicy {
    private Win64ParentCodePolicy() {}

    public static final int MAX_PARENT_FRAGMENT_BYTES=4096;
    public static final int MAX_TOTAL_PARENT_SOURCE_BYTES=2*1024*1024;
    public static final int MAX_PARENT_FRAGMENT_COUNT=1024;

    public static int checkedLength(long beginRva,long endRva,
                                    long unwindRva) {
        if(beginRva<=0 || endRva<=beginRva ||
           endRva>0xffffffffL || unwindRva<=0 ||
           unwindRva>0xffffffffL)
            throw new IllegalArgumentException("invalid Win64 parent PE chain RVA");
        long length=endRva-beginRva;
        if(length>MAX_PARENT_FRAGMENT_BYTES)
            throw new IllegalArgumentException(
                "parent source fragment exceeds 4096-byte bound");
        return (int)length;
    }

    public static String memberName(long beginRva,long endRva,long unwindRva) {
        checkedLength(beginRva,endRva,unwindRva);
        return String.format(java.util.Locale.ROOT,
                             "parents/rva_%08x.bin",beginRva);
    }

    public static boolean canInclude(int currentCount,long totalExportedBytes,
                                     int nextBytes) {
        return currentCount>=0&&
               currentCount<MAX_PARENT_FRAGMENT_COUNT &&
               totalExportedBytes>=0 &&
               nextBytes>0&&nextBytes<=MAX_PARENT_FRAGMENT_BYTES &&
               totalExportedBytes<=MAX_TOTAL_PARENT_SOURCE_BYTES-nextBytes;
    }
}
