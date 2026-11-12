import com.rm11cor.carxstreet.portlab.PeImportProbe;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class PeImportProbeTest {
    private static int count=0;
    private static void ok(boolean b,String why) {
        if(!b)throw new AssertionError(why);
        count++;
    }
    private static void w16(byte[] b,int p,int x) {
        b[p]=(byte)x;b[p+1]=(byte)(x>>>8);
    }
    private static void w32(byte[] b,int p,int x) {
        w16(b,p,x);w16(b,p+2,x>>>16);
    }
    private static byte[] fixture(int machine,String name,boolean terminator) {
        byte[] b=new byte[4096];
        b[0]='M';b[1]='Z';
        w32(b,0x3c,0x80);
        b[0x80]='P';b[0x81]='E';
        w16(b,0x84,machine);
        w16(b,0x86,1);
        w16(b,0x94,0xf0);
        w16(b,0x98,0x20b);
        int dir=0x98+112+8;
        w32(b,dir,0x2000);
        w32(b,dir+4,40);
        int sec=0x98+0xf0;
        b[sec]='.';b[sec+1]='i';b[sec+2]='d';b[sec+3]='a';b[sec+4]='t';b[sec+5]='a';
        w32(b,sec+8,0x400);
        w32(b,sec+12,0x2000);
        w32(b,sec+16,0x400);
        w32(b,sec+20,0x400);
        w32(b,0x400,0x2100);
        w32(b,0x400+12,0x2050);
        w32(b,0x400+16,0x2100);
        if(!terminator)w32(b,0x414+12,0x2050);
        byte[] n=(name+"\0").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(n,0,b,0x450,n.length);
        return b;
    }
    private static PeImportProbe.Result parse(byte[] b) {
        return PeImportProbe.inspect((off,len)->{
            if(off<0||off+len>b.length)
                throw new IOException("out of sample");
            return Arrays.copyOfRange(b,(int)off,(int)off+len);
        },b.length);
    }
    public static void main(String[] args) {
        var okWin=parse(fixture(0x8664,"KERNEL32.dll",true));
        ok(okWin.valid,"Valid Windows PE header");
        ok(okWin.architecture.equals("Windows-PE-x86_64"),"Original x86-64");
        ok(okWin.importDirectoryFullyRead,"PE import descriptors fully read");
        ok(okWin.importedDlls.size()==1&&okWin.importedDlls.get(0).equals("kernel32.dll"),
                "Original DLL name extracted");
        var steam=parse(fixture(0x8664,"steam_api64.dll",true));
        ok(steam.importedDlls.contains("steam_api64.dll"),"Steam imported library name");
        var arm=parse(fixture(0xaa64,"USER32.dll",true));
        ok(arm.architecture.equals("Windows-PE-ARM64"),"PE ARM64 is still Windows PE not Android ELF");
        var unterm=parse(fixture(0x8664,"d3d11.dll",false));
        ok(unterm.valid&&!unterm.importDirectoryFullyRead &&
                unterm.importedDlls.isEmpty(),"Refuse unterminated import directory");
        byte[] bad=fixture(0x8664,"kernel32.dll",true);
        bad[0]=0;
        ok(!parse(bad).valid,"Reject fake MZ");
        bad=fixture(0x8664,"kernel32.dll",true);
        bad[0x80]=0;
        ok(!parse(bad).valid,"Reject fake PE");
        bad=fixture(0x8664,"kernel32.dll",true);
        w32(bad,0x188+20,9000);
        ok(!parse(bad).valid,"Reject section bytes extending beyond file");
        bad=fixture(0x8664,"kernel32.dll",true);
        w32(bad,0x400+12,0x6000);
        ok(!parse(bad).importDirectoryFullyRead,"Reject invalid DLL RVA");
        bad=fixture(0x8664,"kernel32.dll",true);
        w32(bad,0x98+112+8+4,70000);
        ok(!parse(bad).importDirectoryFullyRead,"Reject giant import directory");
        var truncated=PeImportProbe.inspect((off,len)->new byte[0],8192);
        ok(!truncated.valid,"Reject short SAF content provider reads");
        var unreadable=PeImportProbe.inspect((off,len)->{
            throw new IOException("ESPIPE SAF source isn't seekable");
        },8192);
        ok(!unreadable.valid && !unreadable.importDirectoryFullyRead,
                "Report non-seekable SAF rather than forge import evidence");
        bad=fixture(0x14c,"KERNEL32.dll",true);
        w16(bad,0x98,0x10b);
        ok(parse(bad).format.equals("PE32"),"PE32 parser remains bounded");
        System.out.println("CARX_SAF_PE_IMPORT_PROBE_"+count+"_CORRUPTION_AND_SOURCE_TESTS_PASS");
    }
}
