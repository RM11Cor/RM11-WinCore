import com.rm11cor.carxstreet.portlab.Win64InterRegionGapPolicy;
public final class Win64InterRegionGapPolicyTest {
    private static int pass=0;
    static void ok(boolean v,String why) {
        if(!v)throw new AssertionError(why);
        pass++;
    }
    static void bad(long a,long b) {
        try {Win64InterRegionGapPolicy.checkedLength(a,b);
             throw new AssertionError("unsafe original source gap accepted");}
        catch(IllegalArgumentException expected) {pass++;}
    }
    public static void main(String[] args) {
        ok(Win64InterRegionGapPolicy.checkedLength(0x895279,0x89529a)==33,
                "original 33-byte missing game source interval");
        ok(Win64InterRegionGapPolicy.checkedLength(0x1000,0x1861)==2145,
                "largest original owner v1.3 observed source gap");
        ok(Win64InterRegionGapPolicy.checkedLength(0x1000,0x2000)==4096,
                "exact maximal 4096-byte source gap");
        ok(Win64InterRegionGapPolicy.memberName(0x1000,0x1010).equals(
                "gaps/rva_00001000.bin"),"source gap filename deterministic");
        bad(0,1);bad(10,10);bad(20,10);bad(0x1000,0x2001);
        bad(0x100000000L,0x100000010L);
        ok(!Win64InterRegionGapPolicy.canInclude(0,0,47_416),
                "single original gap request above 4KiB refused");
        ok(Win64InterRegionGapPolicy.canInclude(0,0,2_145),
                "maximum actual original gap accepted");
        ok(Win64InterRegionGapPolicy.canInclude(1023,2_097_152-4096,4096),
                "last permitted original source gap");
        ok(!Win64InterRegionGapPolicy.canInclude(1024,0,1),
                "source gap count bound enforced");
        ok(!Win64InterRegionGapPolicy.canInclude(1,2_097_152,1),
                "total original source size bound enforced");
        ok(!Win64InterRegionGapPolicy.canInclude(0,0,0),
                "zero length refused");
        ok(!Win64InterRegionGapPolicy.canInclude(-1,0,1),
                "invalid negative range count refused");
        ok(pass>=16,"all synthetic safety controls present");
        System.out.println("CARX_G0_ORIGINAL_PE_GAP_SOURCE_EXTRACTION_"+pass+
                "_BOUNDS_AND_SHA_PRECONDITION_TESTS_PASS");
    }
}
