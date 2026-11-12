import com.rm11cor.carxstreet.portlab.Win64UnwindDiverseSampler;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Random;

public final class Win64UnwindDiverseSamplerTest {
    private static int passed=0;
    private static void ok(boolean yes,String message) {
        if(!yes)throw new AssertionError(message);
        passed++;
    }

    private static void assertUnique(Win64UnwindDiverseSampler sampler) {
        var samples=sampler.chosenByBeginRva();
        var keys=new HashSet<Long>();
        long previous=-1;
        for(var item:samples) {
            ok(keys.add(item.unwind),"A duplicated unwind RVA consumed two slots");
            ok(item.begin>previous,"Sample list not sorted by original source RVA");
            previous=item.begin;
        }
        ok(keys.size()==sampler.distinctUnwindRvasSelected(),
                "Selected unique metadata count differs from source samples");
    }

    private static long[] row(int n,long unwind) {
        return new long[]{0x1000L+(long)n*64,0x1000L+(long)n*64+20,unwind};
    }

    private static String fingerprint(Win64UnwindDiverseSampler s) {
        StringBuilder b=new StringBuilder();
        for(var x:s.chosenByBeginRva())
            b.append(x.begin).append(':').append(x.end).append(':')
                    .append(x.unwind).append(';');
        return b.toString();
    }

    public static void main(String[] args) {
        Win64UnwindDiverseSampler one=new Win64UnwindDiverseSampler(256);
        for(int i=0;i<24;i++)one.accept(0x1000L+i*64,0x1000L+i*64+20,0x7000);
        ok(one.totalValidOriginalPdataRegionsSeen()==24,"All 24 source ranges observed");
        ok(one.distinctUnwindRvasSelected()==1,
                "24 source methods with the same xdata RVA cannot dominate reservoir");
        assertUnique(one);

        Win64UnwindDiverseSampler distinct=new Win64UnwindDiverseSampler(256);
        for(int i=0;i<350;i++)
            distinct.accept(0x1000L+i*64,0x1000L+i*64+20,0x8000L+i*4);
        ok(distinct.distinctUnwindRvasSelected()==256,"256 independent metadata groups retained");
        ok(distinct.totalValidOriginalPdataRegionsSeen()==350,
                "Full source entry count remains accurate");
        assertUnique(distinct);

        // Stable across changes in original PE .pdata table ordering.
        ArrayList<long[]> fixture=new ArrayList<>();
        for(int i=0;i<1000;i++)fixture.add(row(i,0x200000L+i*4L));
        for(int i=1000;i<1800;i++)
            fixture.add(row(i,0x200000L+(i%40)*4L));
        var forward=new Win64UnwindDiverseSampler(256);
        for(long[] x:fixture)forward.accept(x[0],x[1],x[2]);
        var reverse=new Win64UnwindDiverseSampler(256);
        Collections.reverse(fixture);
        for(long[] x:fixture)reverse.accept(x[0],x[1],x[2]);
        var shuffled=new Win64UnwindDiverseSampler(256);
        Collections.shuffle(fixture,new Random(730642L));
        for(long[] x:fixture)shuffled.accept(x[0],x[1],x[2]);
        ok(fingerprint(forward).equals(fingerprint(reverse)),
                "Unwind group selection changes when entries reversed");
        ok(fingerprint(forward).equals(fingerprint(shuffled)),
                "Unwind group selection changes when entries shuffled");
        ok(forward.totalValidOriginalPdataRegionsSeen()==1800,
                "All 1800 synthetic source entries accounted for");
        assertUnique(shuffled);

        var small=new Win64UnwindDiverseSampler(3);
        for(int i=0;i<500;i++)
            small.accept(0x1000L+i*16,0x1000L+i*16+5,0x10000L+i*4L);
        ok(small.distinctUnwindRvasSelected()==3,"Tiny bounded cap exceeded");
        assertUnique(small);

        var older=new Win64UnwindDiverseSampler(256);
        // Simulate actual v1.0 user report: 149 distinct unwind metadata RVAs
        // across 256 source fragments, including one group with 24 records.
        for(int i=0;i<149;i++)older.accept(0x10000L+i*128,0x10000L+i*128+30,0x60000L+i*4);
        for(int i=0;i<107;i++)
            older.accept(0x30000L+i*64,0x30000L+i*64+30,0x60000L+(i%21)*4);
        ok(older.totalValidOriginalPdataRegionsSeen()==256,
                "Source-fragment count preserved");
        ok(older.distinctUnwindRvasSelected()==149,
                "Representative count is unique xdata, not unique IL2CPP method");
        assertUnique(older);

        for(int bad: new int[]{0,-1,4097}) {
            try {
                new Win64UnwindDiverseSampler(bad);
                throw new AssertionError("Invalid bounded sampler limit accepted");
            }catch(IllegalArgumentException expected) {passed++;}
        }

        try {
            one.accept(0,0,0);
            throw new AssertionError("Zero length / invalid PE source RVA accepted");
        }catch(IllegalArgumentException expected) {passed++;}

        System.out.println(
            "CARX_G0_DIVERSE_PDATA_UNWIND_RVA_SAMPLER_"+passed+
            "_CONTROLS_PASS; 1800_ENTRY_ORDER_INDEPENDENCE; 256_MAX_BOUNDED");
    }
}
