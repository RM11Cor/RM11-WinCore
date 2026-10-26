package com.rm11.autocore.runtime;

/**
 * Complete-line, bounded evidence capture for an opt-in game-only native
 * abort() LD_PRELOAD. The first reported ELF image/offset is retained even
 * when Wine emits hundreds of thousands of unwind lines afterwards.
 */
public final class WineNativeAbortEvidence {
    private final StringBuilder line=new StringBuilder();
    private String image="UNKNOWN";
    private String offset="UNKNOWN";
    private boolean seen;
    private long linesRead;
    public synchronized void accept(String chunk) {
        if(chunk==null)return;
        for(int i=0;i<chunk.length();i++) {
            char c=chunk.charAt(i);
            if(c=='\n') {
                handle(line.toString());
                line.setLength(0);
            }else if(line.length()<500)line.append(c);
        }
    }
    private void handle(String data) {
        linesRead++;
        if(data.equals("RM11_V465_NATIVE_ABORT_CALLER_SEEN=true"))seen=true;
        if(data.startsWith("RM11_V465_NATIVE_ABORT_CALLER_IMAGE=")
                &&image.equals("UNKNOWN")) {
            String found=data.substring(data.indexOf('=')+1);
            if(found.matches("[A-Za-z0-9_.+\\-]{1,95}"))image=found;
        }
        if(data.startsWith("RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET=")
                &&offset.equals("UNKNOWN")) {
            String found=data.substring(data.indexOf('=')+1);
            if(found.matches("0x[0-9a-fA-F]{1,16}"))offset=found;
        }
    }
    public synchronized String snapshot() {
        return "RM11_V465_ABORT_PRECALL_EVIDENCE\n"
                +"RM11_V465_NATIVE_ABORT_CALLER_SEEN="+seen+"\n"
                +"RM11_V465_NATIVE_ABORT_CALLER_IMAGE="+image+"\n"
                +"RM11_V465_NATIVE_ABORT_CALLER_ELF_OFFSET="+offset+"\n"
                +"RM11_V465_STREAM_LINES="+linesRead+"\n";
    }
}
