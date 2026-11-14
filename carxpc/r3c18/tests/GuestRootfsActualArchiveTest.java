package com.r4.carxpc;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public final class GuestRootfsActualArchiveTest {
    public static void main(String[] args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("archive.tar.gz owned-files-dir");
        Path archive=Paths.get(args[0]),app=Paths.get(args[1]);
        Files.createDirectories(app);
        try(InputStream in=Files.newInputStream(archive)){
            GuestRootfsInstaller.Receipt receipt=GuestRootfsInstaller.install(in,app);
            if(!receipt.sha256.equals(GuestRootfsInstaller.ARCHIVE_SHA256))
                throw new AssertionError("UPSTREAM_SHA_CHANGED");
            if(receipt.entries<1000||receipt.regularBytes<1000000)
                throw new AssertionError("ROOTFS_MANIFEST_SUSPICIOUSLY_SMALL");
            for(String required:Arrays.asList(
                "usr/share/wine/wine.inf",
                "usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll",
                "usr/lib/wine/wine64",
                "tmp/kernix-real-win32-smoke.exe")) {
                if(!Files.isRegularFile(receipt.root.resolve(required)))
                    throw new AssertionError("REQUIRED_BROKEN:"+required);
            }
            System.out.println("CARX_R3C18_REAL_UBUNTU_GUEST_ROOTFS_EXTRACT_SHA256_PASS"+
              " entries="+receipt.entries+
              " regular_bytes="+receipt.regularBytes+
              " symbolic_links="+receipt.symlinks+
              " hard_links="+receipt.hardlinks);
            System.out.println("CARX_R3C18_DISK_STAGING_ONLY_NOT_AN_ANDROID_WINE_EXECUTION");
        }
    }
}
