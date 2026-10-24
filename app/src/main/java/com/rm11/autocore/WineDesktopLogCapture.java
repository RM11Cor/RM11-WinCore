package com.rm11.autocore;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Bounded log capture for long-running Wine IPC diagnostics.
 * Preserve first boot bytes + newest errors; the previous v3.0.3
 * head-only capture lost the driver/font/desktop failures once
 * +process,+x11drv filled its 24K log budget.
 */
public final class WineDesktopLogCapture {
    private final ByteArrayOutputStream head=new ByteArrayOutputStream(2048);
    private final byte[] tail=new byte[16384];
    private int cursor,used;
    private long seen;

    public synchronized void append(byte[] data,int offset,int length) {
        if(data==null||offset<0||length<0||offset>data.length-length)
            throw new IllegalArgumentException("invalid bounded Wine log write");
        int first=Math.min(length,Math.max(0,2048-head.size()));
        head.write(data,offset,first);
        for(int i=0;i<length;i++) {
            tail[cursor]=data[offset+i];
            cursor=(cursor+1)%tail.length;
            if(used<tail.length)used++;
        }
        seen+=length;
    }

    public synchronized String snapshot() {
        byte[] bytes=new byte[used];
        int start=seen>tail.length ? cursor : 0;
        for(int i=0;i<used;i++)bytes[i]=tail[(start+i)%tail.length];
        String last=new String(bytes,StandardCharsets.UTF_8);
        if(seen<=tail.length)return last;
        return new String(head.toByteArray(),StandardCharsets.UTF_8)
                +"\n[RM11_V304_LOG_MIDDLE_OMITTED total="+seen+" bytes]\n"+last;
    }
}
