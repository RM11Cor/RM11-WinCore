package com.rm11.autocore.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

/**
 * Bounded live capture of Wine/FEX stdout+stderr. Never blocks until process
 * exit before making diagnostic output available; the process writer cannot
 * deadlock on a full pipe while its X11 window is missing.
 */
public final class WineGameOutputTail {
    private WineGameOutputTail() {}
    private static final int MAX_CHARS=14000;

    public static String append(String before,String chunk) {
        String old=before==null?"":before;
        String add=chunk==null?"":chunk;
        String combined=old+add;
        return combined.length()>MAX_CHARS
                ?combined.substring(combined.length()-MAX_CHARS)
                :combined;
    }

    public static void drain(InputStream input,Consumer<String> currentOutput)
            throws IOException {
        drain(input,currentOutput,chunk->{});
    }

    public static void drain(InputStream input,Consumer<String> currentOutput,
                             Consumer<String> diagnosticChunks)throws IOException {
        byte[] buf=new byte[2048];
        String tail="";
        for(int size;(size=input.read(buf))!=-1;) {
            if(size==0)continue;
            String chunk=new String(buf,0,size,StandardCharsets.UTF_8);
            diagnosticChunks.accept(chunk);
            tail=append(tail,chunk);
            currentOutput.accept(tail);
        }
    }
}
