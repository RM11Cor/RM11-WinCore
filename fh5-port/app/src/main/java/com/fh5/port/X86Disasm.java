package com.fh5.port;

import org.json.JSONObject;

/**
 * A bounded disassembler, not an x86 emulator and not a Windows launcher.
 * Reports only mnemonic families/summary, never raw original Forza code.
 */
public final class X86Disasm {
    private X86Disasm() {}
    private static final boolean NATIVE_LOADED;
    static {
        boolean ok=false;
        try {System.loadLibrary("fh5_x64_disasm");ok=true;}
        catch(LinkageError | SecurityException ignored) {}
        NATIVE_LOADED=ok;
    }
    private static native String nativeInspect(byte[] bytes,long startRva,long sizeOfImage);
    public static JSONObject inspect(byte[] bytes,long startRva,long sizeOfImage) {
        JSONObject out=new JSONObject();
        try {
            if(!NATIVE_LOADED) {
                out.put("status","capstone_native_library_unavailable");
            } else if(bytes==null || bytes.length<1 || bytes.length>512 || startRva<0 || sizeOfImage<=0 || startRva>=sizeOfImage) {
                out.put("status","entry_sample_invalid");
            } else {
                out=new JSONObject(nativeInspect(bytes,startRva,sizeOfImage));
            }
            out.put("game_code_executed",false);
            out.put("original_game_bytes_exported",false);
            out.put("windows_process_loaded",false);
            out.put("full_decoder_does_not_imply_full_translator",true);
            return out;
        } catch(Exception e) {
            try {
                out.put("status","native_disassembly_result_error");
                out.put("error_class",e.getClass().getSimpleName());
                out.put("game_code_executed",false);
                out.put("original_game_bytes_exported",false);
            } catch(Exception ignored) {}
            return out;
        }
    }
}
