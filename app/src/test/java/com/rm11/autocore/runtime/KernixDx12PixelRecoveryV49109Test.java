package com.rm11.autocore.runtime;

import org.junit.Test;
import static org.junit.Assert.*;

/** v49109: post-session DX12 qualification must reject stale or incomplete pixels. */
public final class KernixDx12PixelRecoveryV49109Test {
    private static String pixel(int index,int count,int mask){
        return "KERNIX_V49106_SAMPLE_INDEX="+index+"\n"
            +"KERNIX_DX12_PIXELCOPY=SUCCESS\n"
            +"KERNIX_DX12_EXPECTED_COLOR_VISIBLE=true\n"
            +"KERNIX_V49106_DISTINCT_ANDROID_COLORS="+count+"\n"
            +"KERNIX_V49106_COLOR_MASK="+mask+"\n";
    }
    @Test public void acceptDistinctPixelCopyColors(){
        assertEquals(15,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,4,15)));
        assertEquals(3,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(4,2,3)));
    }
    @Test public void rejectSingleOrForgedAggregate(){
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,1,1)));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,4,3)));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,2,1)));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(11,4,15)));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(0,4,15)));
    }
    @Test public void rejectMissingSurfaceOrFailedPixelCopy(){
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,4,15).replace(
                "PIXELCOPY=SUCCESS","PIXELCOPY=RESULT_3")));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,4,15).replace(
                "EXPECTED_COLOR_VISIBLE=true","EXPECTED_COLOR_VISIBLE=false")));
        assertEquals(0,KernixEngineQualificationV49090
            .verifiedDx12PixelMask(pixel(10,4,15).replace(
                "COLOR_MASK=15","COLOR_BITS_UNKNOWN=15")));
    }
}
