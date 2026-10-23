package com.rm11.autocore.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;
import static org.junit.Assert.*;

public final class ExternalExePilotPolicyTest {
    private RuntimeLayout layout(Path temp) throws Exception {
        Path files=temp.resolve("files");
        Path libs=temp.resolve("native");
        Files.createDirectories(files);
        Files.createDirectories(libs);
        Files.createDirectories(files.resolve("external-exe-pilot"));
        return new RuntimeLayout(files, libs);
    }

    private Path makeExe(RuntimeLayout layout, int machine, int magic) throws Exception {
        byte[] image=new byte[1024];
        image[0]='M';image[1]='Z';
        image[0x3c]=(byte)0x80;
        image[0x80]='P';image[0x81]='E';
        image[0x84]=(byte)(machine&255);image[0x85]=(byte)((machine>>>8)&255);
        image[0x98]=(byte)(magic&255);image[0x99]=(byte)((magic>>>8)&255);
        Path path=layout.appFiles.resolve("external-exe-pilot/rm11-import-test.exe");
        Files.write(path,image);
        return path;
    }

    @Test public void detectsSubsystemFromPe32PlusHeader() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-pe-subsystem-"));
        Path exe=makeExe(p,0x8664,0x20b);
        // e_lfanew=0x80; optional header=0x98; subsystem=optional+68=0xDC
        try (java.io.RandomAccessFile file=new java.io.RandomAccessFile(exe.toFile(),"rw")) {
            file.seek(0xDC);
            file.write(2);
            file.write(0);
        }
        assertEquals(2, ExternalExePilotPolicy.readPeSubsystem(p,exe));
        try (java.io.RandomAccessFile file=new java.io.RandomAccessFile(exe.toFile(),"rw")) {
            file.seek(0xDC);
            file.write(3);
            file.write(0);
        }
        assertEquals(3, ExternalExePilotPolicy.readPeSubsystem(p,exe));
    }

    @Test public void acceptsOnlyPrivatePe64X86_64Header() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-exe-"));
        Path f=makeExe(p,0x8664,0x20b);
        ExternalExePilotPolicy.validate(p,f);
    }

    @Test public void refusesPe32OrWrongArchitecture() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-exe-arch-"));
        Path f=makeExe(p,0x14c,0x10b);
        try {ExternalExePilotPolicy.validate(p,f);fail();}
        catch(java.io.IOException expected) {}
    }

    @Test public void refusesSymlinkAndOutsidePrivateFolder() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-exe-link-"));
        Path src=makeExe(p,0x8664,0x20b);
        Path target=src.resolveSibling("rm11-import-link.exe");
        Files.createSymbolicLink(target,src);
        try {ExternalExePilotPolicy.validate(p,target);fail();}
        catch(java.io.IOException expected) {}
        Path elsewhere=p.appFiles.resolve("rm11-import-outside.exe");
        Files.copy(src,elsewhere);
        try {ExternalExePilotPolicy.validate(p,elsewhere);fail();}
        catch(java.io.IOException expected) {}
    }

    @Test public void refusesLargerThanLimit() throws Exception {
        RuntimeLayout p=layout(Files.createTempDirectory("rm11-exe-large-"));
        Path exe=makeExe(p,0x8664,0x20b);
        try (java.io.RandomAccessFile f=new java.io.RandomAccessFile(exe.toFile(),"rw")) {
            f.setLength(ExternalExePilotPolicy.MAX_EXE_BYTES+1);
        }
        try {ExternalExePilotPolicy.validate(p,exe);fail();}
        catch(java.io.IOException expected) {}
    }
}
