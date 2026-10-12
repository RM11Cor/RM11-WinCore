import com.rm11.wincore.RuntimeBinaryAudit;
import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Locale;

public class RuntimeBinaryAuditTest {
    static String sha(byte[] bytes) throws Exception {
        StringBuilder b = new StringBuilder();
        for (byte v : MessageDigest.getInstance("SHA-256").digest(bytes))
            b.append(String.format(Locale.US, "%02x", v & 255));
        return b.toString();
    }
    static void put16(byte[] b, int p, int v) { b[p] = (byte)v; b[p+1] = (byte)(v >> 8); }
    static void put32(byte[] b, int p, int v) { for (int i=0;i<4;i++) b[p+i]=(byte)(v>>(i*8)); }
    static void put64(byte[] b, int p, int v) { put32(b,p,v); }
    static void check(boolean yes) { if (!yes) throw new AssertionError("audit expectation failed"); }
    public static void main(String[] args) throws Exception {
        File f = File.createTempFile("rm11-v10-", ".blob");
        try {
            byte[] sample = "not wine or box64".getBytes("UTF-8");
            Files.write(f.toPath(), sample);
            RuntimeBinaryAudit.Result plain = RuntimeBinaryAudit.inspect(f, sample.length, sha(sample));
            check(!plain.isElf && plain.elf == null && !plain.isNativeArm64());
            boolean rejected = false;
            try { RuntimeBinaryAudit.inspect(f, sample.length, "0".repeat(64)); }
            catch (java.io.IOException expected) { rejected = true; }
            check(rejected);
            byte[] elf = new byte[256];
            elf[0]=0x7f;elf[1]='E';elf[2]='L';elf[3]='F';elf[4]=2;elf[5]=1;elf[6]=1;
            put16(elf,16,3); put16(elf,18,183); put64(elf,32,64);
            put16(elf,54,56); put16(elf,56,1);
            put32(elf,64,1); put64(elf,64+8,0); put64(elf,64+16,0); put64(elf,64+32,256);
            Files.write(f.toPath(),elf);
            RuntimeBinaryAudit.Result nativeArm = RuntimeBinaryAudit.inspect(f,elf.length,sha(elf));
            check(nativeArm.isElf && nativeArm.isNativeArm64() && !nativeArm.usesGlibcLoader());
            put16(elf,18,62);
            Files.write(f.toPath(),elf);
            check(!RuntimeBinaryAudit.inspect(f,elf.length,sha(elf)).isNativeArm64());
            byte[] broken = new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
            Files.write(f.toPath(),broken);
            RuntimeBinaryAudit.Result unreadable = RuntimeBinaryAudit.inspect(f,broken.length,sha(broken));
            check(unreadable.isElf && unreadable.elf == null && unreadable.metadataError != null);
            System.out.println("PASS: V1.0 staged binary re-hash, inert data, ARM64/x86 ELF discrimination, truncated ELF");
        } finally { f.delete(); }
    }
}
