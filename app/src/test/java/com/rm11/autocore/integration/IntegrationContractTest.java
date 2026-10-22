package com.rm11.autocore.integration;

import com.rm11.autocore.runtime.RuntimeLayout;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class IntegrationContractTest {
    @Test public void bionicAndGlibcAreDistinct() {
        RuntimeCatalog.Profile b = RuntimeCatalog.profile(RuntimeCatalog.Backend.BIONIC_ARM64EC_FEX);
        RuntimeCatalog.Profile g = RuntimeCatalog.profile(RuntimeCatalog.Backend.GLIBC_BOX64);
        assertNotEquals(b.libc, g.libc);
        assertNotEquals(b.cpuTranslator, g.cpuTranslator);
        assertFalse(b.requiresLinuxRootFs);
        assertTrue(g.requiresLinuxRootFs);
    }
    @Test(expected=IllegalArgumentException.class) public void incompatibleRuntimeMustNotBeStacked() {
        RuntimeCatalog.requireCompatible(RuntimeCatalog.Backend.BIONIC_ARM64EC_FEX,
                RuntimeCatalog.profile(RuntimeCatalog.Backend.GLIBC_BOX64).libc,
                RuntimeCatalog.profile(RuntimeCatalog.Backend.BIONIC_ARM64EC_FEX).cpuTranslator);
    }
    @Test public void compatibleRuntimeIsAccepted() {
        RuntimeCatalog.Profile p = RuntimeCatalog.profile(RuntimeCatalog.Backend.BIONIC_ARM64EC_FEX);
        RuntimeCatalog.requireCompatible(p.backend, p.libc, p.cpuTranslator);
    }
    private static Path prefix(Path base) throws IOException {
        Path p = base.resolve("prefix");
        Files.createDirectories(p.resolve("dosdevices"));
        Files.createFile(p.resolve(".rm11-prefix-complete"));
        return p;
    }
    @Test public void gameFolderMappedWithoutCopying() throws Exception {
        Path base=Files.createTempDirectory("rm11-drive-test");
        Path p=prefix(base), game=Files.createDirectory(base.resolve("my-game"));
        Files.write(game.resolve("game.exe"),new byte[]{77,90});
        Path link=WineDriveMapper.mapExistingGameDirectory(p,game,'D');
        assertTrue(Files.isSymbolicLink(link));
        assertEquals(game.toRealPath(),Files.readSymbolicLink(link));
        assertTrue(Files.exists(game.resolve("game.exe")));
    }
    @Test public void existingDriveNeverOverwritten() throws Exception {
        Path base=Files.createTempDirectory("rm11-existing-drive");
        Path p=prefix(base), game=Files.createDirectory(base.resolve("game"));
        Path link=p.resolve("dosdevices/d:");
        Files.write(link,new byte[]{1});
        try { WineDriveMapper.mapExistingGameDirectory(p,game,'d'); fail("expected refusal"); }
        catch(IOException expected) { assertArrayEquals(new byte[]{1},Files.readAllBytes(link)); }
    }
    @Test public void reservedDriveRefused() throws Exception {
        Path base=Files.createTempDirectory("rm11-reserved");
        try { WineDriveMapper.mapExistingGameDirectory(prefix(base),base,'c'); fail(); }
        catch(IOException expected) { assertTrue(expected.getMessage().contains("D:")); }
    }
    @Test public void nonCommittedPrefixRefused() throws Exception {
        Path base=Files.createTempDirectory("rm11-prefix");
        Files.createDirectories(base.resolve("dosdevices"));
        try { WineDriveMapper.mapExistingGameDirectory(base,Files.createDirectory(base.resolve("game")),'d'); fail(); }
        catch(IOException expected) { assertTrue(expected.getMessage().contains("not committed")); }
    }
    @Test public void auditNeverPretendsToRunExe() throws Exception {
        Path base=Files.createTempDirectory("rm11-audit");
        RuntimeLayout layout=new RuntimeLayout(base,base.resolve("native"));
        String report=RuntimeIntegrationAudit.report(layout);
        assertTrue(report.contains("READ ONLY"));
        assertTrue(report.contains("MISSING: native WineServer"));
        assertTrue(report.contains("Native child re-exec: NOT VERIFIED"));
        assertTrue(report.contains("GLIBC_BOX64"));
    }
    @Test public void elf64ReaderExtractsInterpreterAndDependencies() throws Exception {
        Path f=Files.createTempFile("rm11-elf64", ".so");
        java.nio.ByteBuffer b=java.nio.ByteBuffer.allocate(700).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        b.put(0,(byte)127); b.put(1,(byte)'E'); b.put(2,(byte)'L'); b.put(3,(byte)'F');
        b.put(4,(byte)2); b.put(5,(byte)1); b.putShort(18,(short)183);
        b.putLong(32,64); b.putShort(54,(short)56); b.putShort(56,(short)3);
        // Load range maps vaddr 0x1000 to file offset 256.
        b.putInt(64,1); b.putLong(64+8,256); b.putLong(64+16,4096); b.putLong(64+32,256);
        // Dynamic section at file offset 300: DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_NULL.
        int ph=64+56; b.putInt(ph,2); b.putLong(ph+8,300); b.putLong(ph+16,4096+44); b.putLong(ph+32,64);
        // PT_INTERP in a non-overlapping file range.
        ph=64+112; b.putInt(ph,3); b.putLong(ph+8,600);
        byte[] interp="/system/bin/linker64\0".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        b.putLong(ph+32,interp.length);
        b.position(600); b.put(interp);
        b.putLong(300,1); b.putLong(308,1);
        b.putLong(316,5); b.putLong(324,4096+144);
        b.putLong(332,10); b.putLong(340,9);
        b.position(400); b.put((byte)0); b.put("libc.so".getBytes(java.nio.charset.StandardCharsets.UTF_8)); b.put((byte)0);
        Files.write(f,b.array());
        Elf64Inspection.Result e=Elf64Inspection.inspect(f);
        assertTrue(e.arm64);
        assertEquals("/system/bin/linker64", e.interpreter);
        assertTrue(e.needed.contains("libc.so"));
    }
    @Test(expected=IOException.class) public void rejectInvalidElf() throws Exception {
        Path file=Files.createTempFile("rm11-elf",".so");
        Files.write(file,new byte[]{77,90,1,2});
        Elf64Inspection.inspect(file);
    }
}
