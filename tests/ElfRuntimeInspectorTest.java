import com.rm11.wincore.ElfRuntimeInspector;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ElfRuntimeInspectorTest {
    static void w16(byte[] b, int p, int x) { b[p] = (byte)x; b[p+1] = (byte)(x >>> 8); }
    static void w32(byte[] b, int p, long x) { w16(b,p,(int)x); w16(b,p+2,(int)(x>>>16)); }
    static void w64(byte[] b, int p, long x) { w32(b,p,x); w32(b,p+4,x>>>32); }
    static void ph(byte[] b, int p, int type, int off, int va, int len) {
        w32(b,p,type); w64(b,p+8,off); w64(b,p+16,va); w64(b,p+32,len);
    }
    static byte[] elf(int machine, String loader, String library) {
        byte[] b = new byte[4096];
        b[0] = 0x7f; b[1]='E'; b[2]='L'; b[3]='F'; b[4]=2; b[5]=1; b[6]=1;
        w16(b,16,3); w16(b,18,machine); w32(b,20,1);
        w64(b,32,64); w16(b,52,64); w16(b,54,56); w16(b,56,3);
        ph(b,64,1,0,0x400000,b.length);
        byte[] t = (loader+"\0").getBytes(StandardCharsets.US_ASCII);
        ph(b,120,3,0x500,0,t.length); System.arraycopy(t,0,b,0x500,t.length);
        ph(b,176,2,0x600,0x400600,0x40);
        w64(b,0x600,5); w64(b,0x608,0x400700); // DT_STRTAB
        w64(b,0x610,10); w64(b,0x618,64); // DT_STRSZ
        w64(b,0x620,1); w64(b,0x628,1); // DT_NEEDED offset 1
        b[0x700]=0;
        byte[] lib=library.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(lib,0,b,0x701,lib.length);
        return b;
    }
    static void ok(boolean b, String m) {if(!b)throw new AssertionError(m);}
    static void bad(byte[] b) throws Exception {
        try { ElfRuntimeInspector.analyzeBytes(b); throw new AssertionError("Expected IOException"); }
        catch (IOException expected) { }
    }
    public static void main(String[] args) throws Exception {
        ElfRuntimeInspector.Report glibc = ElfRuntimeInspector.analyze(
            new ByteArrayInputStream(elf(183,"/lib/ld-linux-aarch64.so.1", "libc.so.6")));
        ok(glibc.machine==183,"ARM64"); ok(glibc.needed.contains("libc.so.6"),"dynamic needed");
        ok(ElfRuntimeInspector.explain(glibc,"box64").contains("LINUX USERLAND REQUIRED"),"glibc warning");
        ElfRuntimeInspector.Report android = ElfRuntimeInspector.analyzeBytes(
            elf(183,"/system/bin/linker64", "libc.so"));
        ok(ElfRuntimeInspector.explain(android,"lib.so").contains("ANDROID LOADER HINT"),"Android loader note");
        ElfRuntimeInspector.Report x64 = ElfRuntimeInspector.analyzeBytes(
            elf(62,"/lib64/ld-linux-x86-64.so.2", "libc.so.6"));
        ok(ElfRuntimeInspector.explain(x64,"wine").contains("NOT NATIVE"),"x86-64 native denial");
        byte[] junk = new byte[4096]; bad(junk);
        byte[] invalid = elf(183,"/system/bin/linker64","libc.so"); w64(invalid,32,0x7fffffffffffffffL); bad(invalid);
        invalid = elf(183,"/system/bin/linker64","libc.so"); w16(invalid,56,65535); bad(invalid);
        invalid = elf(183,"/system/bin/linker64","libc.so"); invalid[5]=2; bad(invalid);
        System.out.println("PASS: ARM64 glibc/Bionic ELF, DT_NEEDED, x64, corrupted ELF and bounds");
    }
}
