package com.rm11.autocore.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AppPrivateStorageTest {
    public static void main(String[] args) throws Exception {
        Path root=Files.createTempDirectory("rm11-private-storage-");
        long bytes=AppPrivateStorage.usableBytes(root);
        if (bytes<=0) throw new AssertionError("Expected positive available space for a writable directory");
        boolean failed=false;
        try { AppPrivateStorage.usableBytes(root.resolve("does-not-exist")); }
        catch (IOException expected) { failed=true; }
        if (!failed) throw new AssertionError("Nonexistent private storage must fail closed");
        System.out.println("PASS: Android-compatible File.getUsableSpace and missing-root guard");
    }
}
