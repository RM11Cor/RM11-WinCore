import com.rm11cor.carxstreet.portlab.Win64UnwindRecordFormat;
import java.io.IOException;

public final class Win64UnwindRecordFormatTest {
    static int passed=0;
    static void ok(boolean condition,String why) {
        if(!condition)throw new AssertionError(why);
        passed++;
    }
    static void rejects(byte[] sample) {
        try {
            Win64UnwindRecordFormat.inspect(sample);
            throw new AssertionError("Unsafe unwind record accepted");
        } catch(IOException expected) {
            passed++;
        }
    }
    static byte[] chain(int begin,int end,int unwind) {
        byte[] raw=new byte[16];
        raw[0]=0x21;
        write32(raw,4,begin);
        write32(raw,8,end);
        write32(raw,12,unwind);
        return raw;
    }
    static void write32(byte[] b,int pos,int n) {
        for(int i=0;i<4;i++)b[pos+i]=(byte)(n >>> (i*8));
    }
    public static void main(String[] unused) throws Exception {
        byte[] noOps=new byte[]{1,0,0,0};
        ok(Win64UnwindRecordFormat.requiredBytes(noOps)==4,"basic record size");
        var empty=Win64UnwindRecordFormat.inspect(noOps);
        ok(!empty.chained && !empty.hasHandler,"no flags record");
        ok(empty.byteLength==4,"exact local record bytes");
        byte[] twoSlots=new byte[]{1,6,2,0,6,0x42,1,0x30};
        ok(Win64UnwindRecordFormat.requiredBytes(twoSlots)==8,"two-slot record");
        ok(Win64UnwindRecordFormat.inspect(twoSlots).slotCount==2,"slot count preserved");
        byte[] oneSlot=new byte[]{1,2,1,0,1,0x30,0,0};
        ok(Win64UnwindRecordFormat.requiredBytes(oneSlot)==8,"odd slot alignment");
        ok(Win64UnwindRecordFormat.inspect(oneSlot).prologBytes==2,"prolog preserved");
        byte[] chained=chain(0x1000,0x10a0,0x2000);
        var c=Win64UnwindRecordFormat.inspect(chained);
        ok(c.chained && c.chainedUnwindRva==0x2000,"true chained xdata target");
        ok(c.chainedBeginRva==0x1000 && c.chainedEndRva==0x10a0,
                "Win64 RUNTIME_FUNCTION Begin/End preserved");
        ok(c.byteLength==16,"trailer size includes 12 byte chain");
        byte[] handler=new byte[8];
        handler[0]=9;write32(handler,4,0x1200);
        ok(Win64UnwindRecordFormat.inspect(handler).hasHandler,"handler trailer");
        rejects(new byte[]{2,0,0,0}); // unsupported newer metadata version
        rejects(new byte[]{0x41,0,0,0}); // reserved flags
        rejects(new byte[]{0x29,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
        rejects(new byte[]{1,0,1,0}); // truncated odd code slot
        rejects(new byte[]{0x21,0,0,0}); // missing chained 12-byte trailer
        rejects(chain(0x1000,0x1000,0x2000)); // zero-length chain
        rejects(chain(0x1000,0x1010,0)); // invalid parent unwind RVA
        rejects(handlerWithZero());
        rejects(new byte[]{1,0,0,0,0}); // reject trailing data
        byte[] many=new byte[528];
        many[0]=0x21;many[2]=(byte)255;
        // 4+2*255=514 aligned 516 plus 12 chain =528
        write32(many,516,0x1000);write32(many,520,0x1020);
        write32(many,524,0x2000);
        ok(Win64UnwindRecordFormat.requiredBytes(many)==528,"full 255-slot bound");
        ok(Win64UnwindRecordFormat.inspect(many).byteLength==528,
                "maximum authorized 528-byte xdata record");
        ok(passed>=20,"all independent synthetic controls exercised");
        System.out.println("CARX_G0_WIN64_UNWIND_XDATA_SOURCE_LAYOUT_"+passed+"_TESTS_PASS");
    }
    static byte[] handlerWithZero() {
        return new byte[]{9,0,0,0,0,0,0,0};
    }
}
