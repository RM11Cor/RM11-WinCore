package com.fh5.port;

import org.json.JSONObject;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Narrow real PE64 x86-64-to-AArch64 execution gate.
 * This explicitly cannot load/execute real Forza Horizon 5 game code.
 */
public final class X64Proof {
    private X64Proof() { }
    private static final boolean NATIVE_LOADED;
    static {
        boolean available;
        try { System.loadLibrary("fh5_x64_micro"); available=true; }
        catch (UnsatisfiedLinkError | SecurityException e) { available=false; }
        NATIVE_LOADED=available;
    }
    private static native String nativeRun(byte[] syntheticPe);
    private static native String nativeInspectBlock(byte[] actualX86EntryBytes);

    /** Never runs a game byte. The old tiny translator is asked to decode
     * the original entrypoint; unsupported instructions are expected. */
    public static JSONObject inspectActualEntry(byte[] bytes) {
        JSONObject out=new JSONObject();
        try {
            if (!NATIVE_LOADED) {
                out.put("status","native_translator_library_not_loaded");
            } else if (bytes==null || bytes.length<1 || bytes.length>512) {
                out.put("status","invalid_bounded_entry_sample");
            } else {
                out=new JSONObject(nativeInspectBlock(bytes));
            }
            out.put("stage","P2_3_ORIGINAL_ENTRY_TRANSLATION_ONLY");
            out.put("raw_entry_bytes_exported",false);
            out.put("original_game_code_executed",false);
            out.put("full_windows_runtime_available",false);
            return out;
        } catch(Exception ex) {
            try {
                out.put("stage","P2_3_TRANSLATOR_PROBE_ERROR");
                out.put("error_class",ex.getClass().getSimpleName());
                out.put("original_game_code_executed",false);
                out.put("raw_entry_bytes_exported",false);
            } catch(Exception ignored) {}
            return out;
        }
    }

    public static byte[] syntheticPe42() {
        // Generated and synthetic, no proprietary game bytes.
        byte[] pe=new byte[1024];
        ByteBuffer b=ByteBuffer.wrap(pe).order(ByteOrder.LITTLE_ENDIAN);
        pe[0]='M';pe[1]='Z';
        b.putInt(0x3c,0x80);
        pe[0x80]='P';pe[0x81]='E';
        b.putShort(0x84,(short)0x8664); // Machine AMD64.
        b.putShort(0x86,(short)1); // One section.
        b.putShort(0x94,(short)0xf0); // Optional header length.
        b.putShort(0x98,(short)0x20b); // PE32+
        b.putInt(0x98+16,0x1000); // Entry point RVA.
        b.putInt(0x98+108,16); // NumberOfRvaAndSizes.
        int section=0x98+0xf0;
        pe[section]='.';pe[section+1]='t';pe[section+2]='e';pe[section+3]='x';pe[section+4]='t';
        b.putInt(section+8,0x200); // Virtual size.
        b.putInt(section+12,0x1000); // RVA.
        b.putInt(section+16,0x200); // Raw size.
        b.putInt(section+20,0x200); // Raw start.
        b.putInt(section+36,0x60000020); // Executable + readable code.
        // mov eax,2; add eax,40; ret. Result must be 42 if run by native ARM64 JIT.
        byte[] program={(byte)0xb8,2,0,0,0,0x05,40,0,0,0,(byte)0xc3};
        System.arraycopy(program,0,pe,0x200,program.length);
        return pe;
    }
    public static JSONObject run() {
        JSONObject obj=new JSONObject();
        try {
            if (!NATIVE_LOADED) {
                obj.put("stage","P2_ARM64_NATIVE_LIBRARY_NOT_LOADED");
                obj.put("executed",false);
                return obj;
            }
            obj=new JSONObject(nativeRun(syntheticPe42()));
            obj.put("stage","P2_SYNTHETIC_PE64_ARM64_EXECUTION");
            obj.put("smoke_result_is_42",obj.optBoolean("executed",false) &&
                obj.optInt("result",-1)==42);
            obj.put("synthetic_only",true);
            obj.put("original_game_code_executed",false);
            obj.put("game_port_complete",false);
            obj.put("external_emulator_invoked",false);
            return obj;
        } catch (Exception ex) {
            try {
                obj.put("stage","P2_NATIVE_OR_REPORT_FAILURE");
                obj.put("exception_class",ex.getClass().getSimpleName());
                obj.put("executed",false);
                obj.put("original_game_code_executed",false);
            } catch (Exception ignored) { }
            return obj;
        }
    }
}
