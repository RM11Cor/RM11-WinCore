import com.rm11cor.carxstreet.portlab.UnitySerializedProbe;
import java.nio.charset.StandardCharsets;

public final class UnitySerializedProbeTest {
    static void ok(boolean b,String why) {
        if(!b)throw new AssertionError("CARX_UNITY_SERIALIZED_HEADER: "+why);
    }
    static byte[] header(int ver,int offset,String unity) {
        byte[] h=new byte[256];
        h[8]=(byte)(ver>>>24);
        h[9]=(byte)(ver>>>16);
        h[10]=(byte)(ver>>>8);
        h[11]=(byte)ver;
        h[16]=0;
        byte[] bytes=unity.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes,0,h,offset,bytes.length);
        return h;
    }
    public static void main(String[] args) {
        var modern=UnitySerializedProbe.inspect(header(22,48,"2022.3.62f1"));
        ok(modern.headerPlausible && modern.serializedFormat==22 &&
            modern.candidateFromKnownHeader && modern.endianFlag==0 &&
            modern.unityVersionCandidate.equals("2022.3.62f1"),
            "v22 Unity version from metadata offset48, not bundle 5.x.x");
        var newer=UnitySerializedProbe.inspect(header(24,48,"6000.0.48f1"));
        ok(newer.candidateFromKnownHeader &&
            newer.unityVersionCandidate.equals("6000.0.48f1"),
            "Unity6 version accepted in source");
        var old=UnitySerializedProbe.inspect(header(21,20,"2020.3.24f1"));
        ok(old.candidateFromKnownHeader &&
            old.unityVersionCandidate.equals("2020.3.24f1"),
            "older Unity v21 offset20");
        var placeholder=UnitySerializedProbe.inspect(header(22,48,"0.0.0"));
        ok(placeholder.headerPlausible && !placeholder.candidateFromKnownHeader,
            "stripped version must not be reported as exact engine");
        var fake=UnitySerializedProbe.inspect(header(22,48,"NotUnity.0"));
        ok(!fake.candidateFromKnownHeader,"fake version rejected");
        byte[] badEndian=header(22,48,"2022.3.62f1");
        badEndian[16]=3;
        ok(!UnitySerializedProbe.inspect(badEndian).headerPlausible,
            "invalid endian flag rejected");
        byte[] badVer=header(2,48,"2022.3.62f1");
        ok(!UnitySerializedProbe.inspect(badVer).headerPlausible,
            "unsupported serialized format rejected");
        ok(!UnitySerializedProbe.inspect(new byte[12]).headerPlausible,
            "truncated header rejected");
        byte[] offsetSpoof=header(22,20,"2022.3.62f1");
        ok(!UnitySerializedProbe.inspect(offsetSpoof).candidateFromKnownHeader,
            "version of modern header must not be read from old offset20");
        System.out.println("CARX_SERIALIZED_HEADER_9_ADVERSARIAL_TESTS_PASS");
    }
}
