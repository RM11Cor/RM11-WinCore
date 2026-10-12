import com.rm11.wincore.WindowsExecutableAnalyzer;
import com.rm11.wincore.SmartGameProfile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class CompatibilityAnalysisTest {
    private static void w16(byte[] d, int off, int n) { d[off] = (byte) n; d[off + 1] = (byte) (n >>> 8); }
    private static void w32(byte[] d, int off, int n) { w16(d, off, n); w16(d, off + 2, n >>> 16); }
    private static byte[] pe(int machine, String dll) {
        byte[] d = new byte[0x800];
        w16(d, 0, 0x5a4d); // MZ
        w32(d, 0x3c, 0x80); // e_lfanew
        w32(d, 0x80, 0x00004550); // PE\0\0
        w16(d, 0x84, machine);
        w16(d, 0x86, 1); // sections
        int opt = 0x80 + 24;
        boolean pe64 = machine == 0x8664;
        w16(d, 0x94, pe64 ? 240 : 224);
        w16(d, opt, pe64 ? 0x20b : 0x10b);
        w32(d, opt + (pe64 ? 108 : 92), 16); // NumberOfRvaAndSizes
        int id = opt + (pe64 ? 112 : 96) + 8; // data dir import
        w32(d, id, 0x1000);
        w32(d, id + 4, 0x40);
        int section = opt + (pe64 ? 240 : 224);
        w32(d, section + 8, 0x400); // virtual size
        w32(d, section + 12, 0x1000); // virtual address
        w32(d, section + 16, 0x400); // raw size
        w32(d, section + 20, 0x400); // raw pos
        w32(d, 0x400 + 12, 0x1100); // DLL string RVA
        byte[] name = dll.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(name, 0, d, 0x500, name.length);
        return d;
    }
    private static void ok(boolean value, String msg) { if (!value) throw new AssertionError(msg); }
    private static void rejects(byte[] file) throws Exception {
        try { WindowsExecutableAnalyzer.analyzeBytes(file, "bad.exe"); throw new AssertionError("Expected reject"); }
        catch (IOException expected) { /* correct */ }
    }
    public static void main(String[] args) throws Exception {
        WindowsExecutableAnalyzer.Result x64 = WindowsExecutableAnalyzer.analyze(
            new ByteArrayInputStream(pe(0x8664, "d3d11.dll")), "test.exe");
        ok(x64.machine == 0x8664, "x64 architecture");
        ok(x64.graphicsHint.equals("D3D11"), "D3D11 parser");
        ok(x64.importsFullyVisible, "import table visibility");
        ok(SmartGameProfile.recommend(x64).contains("Target FPS: 60"), "balanced fps");
        ok(SmartGameProfile.recommend(x64).contains("NOT ACTIVE"), "no fake autotune");
        WindowsExecutableAnalyzer.Result x86 = WindowsExecutableAnalyzer.analyzeBytes(pe(0x014c, "d3d12.dll"), "game.exe");
        ok(x86.graphicsHint.equals("D3D12"), "D3D12 parser");
        ok(x86.architecture().contains("x86-32"), "x86 architecture");
        ok(SmartGameProfile.recommend(x86).contains("Target FPS: 30"), "D3D12 initial fps");
        byte[] corrupt = pe(0x8664, "d3d11.dll");
        corrupt[0] = 0;
        rejects(corrupt);
        corrupt = pe(0x8664, "d3d11.dll");
        w32(corrupt, 0x3c, 0x7fffffff);
        rejects(corrupt);
        corrupt = pe(0x8664, "d3d11.dll");
        w16(corrupt, 0x86, 999);
        rejects(corrupt);
        corrupt = pe(0x8664, "d3d11.dll");
        w32(corrupt, 0x400 + 12, 0x100000); // out-of-bounds import string
        WindowsExecutableAnalyzer.Result partial = WindowsExecutableAnalyzer.analyzeBytes(corrupt, "game.exe");
        ok(!partial.importsFullyVisible, "inaccessible data is marked incomplete");
        ok(partial.graphicsHint.equals("UNKNOWN"), "no fabricated graphics info");
        System.out.println("PASS: x64/x86 synthetic PE, import DLL mapping, balanced suggestions, errors, limits");
    }
}
