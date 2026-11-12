import com.rm11cor.carxstreet.portlab.Win64ParentCodePolicy;

public final class Win64ParentCodePolicyTest {
    private static int passed=0;
    private static void ok(boolean yes,String why) {
        if(!yes)throw new AssertionError(why);
        passed++;
    }
    private static void rejects(long begin,long end,long unwind) {
        try {
            Win64ParentCodePolicy.checkedLength(begin,end,unwind);
            throw new AssertionError("invalid original GameAssembly parent bounds accepted");
        }catch(IllegalArgumentException expected) {passed++;}
    }
    public static void main(String[] args) {
        ok(Win64ParentCodePolicy.checkedLength(0x1000,0x1100,0x2200)==256,
                "source parent size");
        ok(Win64ParentCodePolicy.checkedLength(0x1000,0x147c,0x2200)==1148,
                "owner v1.2 largest original Win64 parent range length");
        ok(Win64ParentCodePolicy.checkedLength(0x1000,0x2000,0x2200)==4096,
                "allowed exact boundary");
        ok(Win64ParentCodePolicy.memberName(0x1000,0x1010,0x2200)
                .equals("parents/rva_00001000.bin"),"deterministic member mapping");
        rejects(0,0x100,0x300);
        rejects(0x1000,0x1000,0x3000);
        rejects(0x1000,0x1001,0);
        rejects(0x1000,0x2001,0x3000);
        rejects(0x100000000L,0x100000002L,0x3000);
        rejects(0x3000,0x1000,0x5000);
        ok(Win64ParentCodePolicy.canInclude(0,0,1148),"first parent");
        ok(Win64ParentCodePolicy.canInclude(1023,2*1024*1024-4096,4096),
                "last bounded parent within total budget");
        ok(!Win64ParentCodePolicy.canInclude(1024,0,1148),
                "never exceed 1024 original parent records");
        ok(!Win64ParentCodePolicy.canInclude(1,2*1024*1024-1000,1148),
                "never exceed 2MiB total source code");
        ok(!Win64ParentCodePolicy.canInclude(0,0,4097),
                "never read >4KiB original PE parent");
        ok(!Win64ParentCodePolicy.canInclude(0,0,0),
                "never export zero source bytes");
        ok(!Win64ParentCodePolicy.canInclude(0,-1,20),
                "never accept negative count");
        ok(passed>=17,"synthetic security invariants covered");
        System.out.println("CARX_G0_ORIGINAL_WIN64_PARENT_CODE_BOUNDARY_"+
                passed+"_TESTS_PASS");
    }
}
