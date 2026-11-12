import com.rm11cor.carxstreet.portlab.UnityFormatProbe;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class UnityFormatProbeTest {
    private static byte[] bundle(String sig, int format, String ver, String rev) throws Exception {
        ByteArrayOutputStream b=new ByteArrayOutputStream();
        b.write(sig.getBytes(StandardCharsets.US_ASCII));
        b.write(0);
        b.write(new byte[]{0,0,0,(byte)format});
        b.write(ver.getBytes(StandardCharsets.US_ASCII));
        b.write(0);
        b.write(rev.getBytes(StandardCharsets.US_ASCII));
        b.write(0);
        return b.toByteArray();
    }
    private static void ok(boolean condition,String msg) {
        if(!condition)throw new AssertionError(msg);
    }
    public static void main(String[] args) throws Exception {
        byte[] meta={(byte)0xAF,0x1B,(byte)0xB1,(byte)0xFA,29,0,0,0};
        var m=UnityFormatProbe.metadata(meta);
        ok(m.classicMagic && m.rawVersion==29 && m.plausibleVersion,
                "original metadata magic is little endian and version 29");
        meta[0]=0;
        ok(!UnityFormatProbe.metadata(meta).classicMagic,
                "forged global metadata magic rejected");
        ok(!UnityFormatProbe.metadata(new byte[]{1,2,3}).classicMagic,
                "truncated original metadata must not be accepted");
        var f=UnityFormatProbe.bundle(bundle("UnityFS",6,"2022.3.30f1","2022.3.30f1"));
        ok(f.recognized && f.headerComplete && f.formatVersion==6
                && f.unityVersion.equals("2022.3.30f1")
                && f.unityRevision.equals("2022.3.30f1"),
                "real UnityFS version revision from bounded header");
        var legacy=UnityFormatProbe.bundle(bundle("UnityWeb",5,"5.6.1f1","5.6.1f1"));
        ok(legacy.recognized && legacy.headerComplete && legacy.formatVersion==5,
                "legacy UnityWeb recognized without claiming Android compatibility");
        ok(!UnityFormatProbe.bundle(bundle("NotUnity",6,"1","1")).recognized,
                "non-Unity content denied");
        ok(!UnityFormatProbe.bundle(new byte[]{'U','n','i','t','y','F','S'}).headerComplete,
                "truncated Unity header not accepted");
        byte[] malformed=bundle("UnityFS",6,"2022.3","2022.3");
        malformed[0]=0x11;
        ok(!UnityFormatProbe.bundle(malformed).recognized,
                "non-printable signature denied");
        ok(!UnityFormatProbe.metadata(new byte[]{(byte)0xAF,0x1B,(byte)0xB1,
                (byte)0xFA,0,0,0,0}).plausibleVersion,
                "metadata version zero not reliable");
        System.out.println("CARX_UNITY_SOURCE_HEADER_PARSER_8_TESTS_PASS_NO_NATIVE_PORT_CLAIM");
    }
}
