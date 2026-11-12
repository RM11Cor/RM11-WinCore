package com.rm11cor.carxstreet.portlab;

import java.nio.charset.StandardCharsets;

/**
 * Small fail-closed Unity SerializedFile header inspector.
 * No type tree, decompression, game asset contents, native binary conversion,
 * or anything that can execute proprietary PC code.
 */
public final class UnitySerializedProbe {
    private UnitySerializedProbe() {}

    public static final class Result {
        public final int serializedFormat;
        public final boolean headerPlausible;
        public final int endianFlag;
        public final String unityVersionCandidate;
        public final String versionPosition;
        public final boolean candidateFromKnownHeader;
        public final String reason;
        private Result(int format,boolean plausible,int endian,String unity,
                       String position,boolean fromHeader,String why) {
            this.serializedFormat=format;
            this.headerPlausible=plausible;
            this.endianFlag=endian;
            this.unityVersionCandidate=unity;
            this.versionPosition=position;
            this.candidateFromKnownHeader=fromHeader;
            this.reason=why;
        }
    }

    public static Result inspect(byte[] prefix) {
        if (prefix == null || prefix.length < 20) {
            return new Result(-1,false,-1,"","none",false,"truncated header");
        }
        // Unity SerializedFile uses big-endian for the initial four 32-bit fields.
        long versionLong=u32be(prefix,8);
        if (versionLong < 7 || versionLong > 50) {
            return new Result((int)versionLong,false,-1,"","none",false,
                    "unrecognized SerializedFile header format");
        }
        int format=(int)versionLong;
        int endian=prefix[16]&0xff;
        if (endian>1) {
            return new Result(format,false,endian,"","none",false,
                    "invalid Unity serialized header endian flag");
        }

        // UnityPy SerializedFile parser: for version 22+ the 20-byte
        // legacy header is followed by metadataSize4 + fileSize8 +
        // dataOffset8 + unknown8 = 48 bytes total. Earlier starts at 20.
        int versionOffset=format>=22?48:20;
        if (prefix.length<=versionOffset) {
            return new Result(format,true,endian,"","none",false,
                    "Unity version header truncated");
        }
        int stop=-1;
        int max=Math.min(prefix.length,versionOffset+48);
        for(int i=versionOffset;i<max;i++) {
            if(prefix[i]==0) {stop=i;break;}
        }
        if(stop<=versionOffset) {
            return new Result(format,true,endian,"","none",false,
                    "Unity version string absent or truncated");
        }
        String text=new String(prefix,versionOffset,stop-versionOffset,
                StandardCharsets.US_ASCII);
        // Unity modern / Unity 6 values, for example 2022.3.62f1
        // or 6000.0.48f1, plus older Unity 5.
        boolean versionPattern=text.matches(
          "(?:(?:20[0-9]{2}|6000|5)\\.[0-9]{1,3}\\.[0-9]{1,3}[abfp][0-9]{1,4})");
        if(!versionPattern) {
            return new Result(format,true,endian,"","none",false,
                    "serialized header Unity editor string unavailable or stripped");
        }
        return new Result(format,true,endian,text,
                "metadata_header_offset_"+versionOffset,true,
                "Unity version candidate from serialized header; not an Android runtime proof");
    }

    private static long u32be(byte[] b,int offset) {
        return (((long)b[offset]&255)<<24)|(((long)b[offset+1]&255)<<16)|
                (((long)b[offset+2]&255)<<8)|((long)b[offset+3]&255);
    }
}
