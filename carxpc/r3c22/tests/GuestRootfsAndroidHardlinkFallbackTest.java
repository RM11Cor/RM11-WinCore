package com.r4.carxpc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/** R3C22: repeatable source-authentic Android16 EACCES hardlink simulation.
 * No root, no Wine or guest program execution; file-data integrity only. */
public final class GuestRootfsAndroidHardlinkFallbackTest {
    private static void check(boolean v,String why){if(!v)throw new AssertionError(why);}
    private static String sha(Path file)throws Exception{
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(file)){
            byte[] b=new byte[65536];int n;
            while((n=in.read(b))!=-1){if(n>0)digest.update(b,0,n);}
        }
        StringBuilder s=new StringBuilder();
        for(byte b:digest.digest())s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    private static GuestRootfsInstaller.Receipt simulated(Path tar,Path app,String digest)
            throws Exception {
        Files.createDirectories(app);
        try(InputStream in=Files.newInputStream(tar)){
            return GuestRootfsInstaller.installFixtureSimulateHardlinkDeniedForUnitTest(
                in,app,digest);
        }
    }
    private static void cleanup(Path path)throws IOException{
        if(!Files.exists(path,LinkOption.NOFOLLOW_LINKS))return;
        try(java.util.stream.Stream<Path> walked=Files.walk(path)){
            List<Path> all=new ArrayList<>();walked.forEach(all::add);
            for(int i=all.size()-1;i>=0;i--)Files.deleteIfExists(all.get(i));
        }
    }
    private static int leakedStages(Path root)throws IOException{
        try(java.util.stream.Stream<Path> walked=Files.list(root)){
            return (int)walked.filter(p->p.getFileName().toString().contains("-stage-")).count();
        }
    }
    private static void synthetic(Path fixtures)throws Exception {
        Path parent=Files.createTempDirectory("carx-r3c22-hardlink-eacces-fixture-");
        try{
            Path good=fixtures.resolve("good.tar.gz");
            GuestRootfsInstaller.Receipt receipt=simulated(good,parent,sha(good));
            Path orig=receipt.root.resolve("usr/lib/wine/wine64");
            Path copied=receipt.root.resolve("usr/bin/wine64");
            check(receipt.hardlinks==1,"FIXTURE_EXPECTS_ONE_HARDLINK");
            check(receipt.hardlinksMaterializedAsCopies==1,
                  "ANDROID_DENIED_HARDLINK_NOT_FALLBACK_COPIED");
            check(Files.isRegularFile(copied,LinkOption.NOFOLLOW_LINKS),
                  "COPIED_GUEST_ALIAS_NOT_REGULAR");
            check(sha(orig).equals(sha(copied)),"FALLBACK_FILE_BYTES_CHANGED");
            check(!Files.isSameFile(copied,orig),"FORCED_COPY_STILL_SAME_INODE");
            check(Files.isSymbolicLink(receipt.root.resolve("usr/bin/wine")),
                  "GUEST_SYMLINK_REGRESSION");
            check(new String(Files.readAllBytes(receipt.root.resolve(".r4-rootfs-receipt")),
                     java.nio.charset.StandardCharsets.UTF_8)
                  .contains("hardlinks_materialized_as_copies=1"),
                  "RECEIPT_MISSING_COPY_MODE");
            check(leakedStages(parent)==0,"SUCCESS_LEFT_STAGING_TREE");
            System.out.println("CARX_R3C22_FORCED_ANDROID_ACCESS_DENIED_HARDLINK_FALLBACK_BYTES_PASS");
            String[] invalid={"traversal","absolute","hardlink_escape","hardlink_symlink",
                              "special_outside_dev","duplicate","checksum_bad"};
            for(String name:invalid){
                boolean rejected=false;
                Path malicious=fixtures.resolve(name+".tar.gz");
                try{simulated(malicious,parent,sha(malicious));}
                catch(IOException e){rejected=true;}
                check(rejected,"UNSAFE_ARCHIVE_ACCEPTED_WITH_HARDLINK_FALLBACK_"+name);
                check(leakedStages(parent)==0,"FAILED_GUEST_ARCHIVE_STAGE_LEFT_"+name);
                check(Files.isSameFile(orig,receipt.root.resolve("usr/lib/wine/wine64")),
                    "PRIOR_VALID_ROOTFS_NOT_KEPT_"+name);
            }
            System.out.println("CARX_R3C22_SEVEN_ATTACK_ARCHIVES_REJECTED_WITH_SAME_ROLLBACK");
        }finally {cleanup(parent);}
    }
    private static void real(Path archive,Path app)throws Exception{
        check(sha(archive).equals(GuestRootfsInstaller.ARCHIVE_SHA256),
              "ORIGINAL_517MB_ARCHIVE_NOT_PINNED");
        GuestRootfsInstaller.Receipt r=simulated(archive,app,
            GuestRootfsInstaller.ARCHIVE_SHA256);
        check(r.entries>5000 && r.symlinks>1000 && r.hardlinks>=1,
              "REAL_WINE_ARCHIVE_INCOMPLETE");
        check(r.hardlinksMaterializedAsCopies==r.hardlinks,
              "NOT_ALL_ANDROID_EACCES_HARDLINKS_COPIED");
        Path perl=r.root.resolve("usr/bin/perl");
        Path perlVersion=r.root.resolve("usr/bin/perl5.38.2");
        check(Files.isRegularFile(perl,LinkOption.NOFOLLOW_LINKS),
              "ANDROID_ACCESS_DENIED_PERL_DESTINATION_NOT_MATERIALIZED");
        check(Files.isRegularFile(perlVersion,LinkOption.NOFOLLOW_LINKS),
              "ANDROID_ACCESS_DENIED_PERL_TARGET_NOT_REGULAR_FILE");
        check(!Files.isSameFile(perl,perlVersion),
              "EACCES_HARDLINK_WRONGLY_EXPECTED_SAME_INODE");
        check(sha(perl).equals(sha(perlVersion)),
              "ANDROID_PERL_LINK_CONTENT_CORRUPTED");
        check(leakedStages(app)==0,"FAILED_STAGE_STILL_PRESENT");
        WineGuestElfPreflight.Result checked=WineGuestElfPreflight.inspect(app);
        check(checked.realX86LinuxElfVerified &&
              checked.guestInterpreterElfVerified &&
              checked.kernel32Pe64Amd64Verified &&
              checked.immediateNeededLibrariesPresent,
              "GUEST_ELF_OR_SHA256_CHECK_REGRESSION_AFTER_HARDLINK_COPY");
        check(!checked.androidWineExecuted && !checked.win64PeAndroidExecuted,
              "READ_ONLY_GUEST_TEST_FALSE_WINE_EXECUTION_CLAIM");
        System.out.println("CARX_R3C22_EXACT_REAL_WINE_SOURCE_SHA256_ANDROID_PERL_HARDLINK_EACCES_SIMULATION_PASS"+
            " archive_sha="+r.sha256+
            " entries="+r.entries+
            " real_hardlinks="+r.hardlinks+
            " materialized_verified_copies="+r.hardlinksMaterializedAsCopies+
            " total_regular_file_bytes="+r.regularBytes+
            " symlinks="+r.symlinks);
        System.out.println("CARX_R3C22_AUTHENTIC_WINE64_LDSO_KERNEL32_SOURCE_SHA256_STILL_VALID");
        System.out.println("CARX_R3C22_ANDROID_EACCES_SIMULATED_HOST_ONLY_NO_REAL_ANDROID_WINE_EXECUTION_PROOF");
    }
    public static void main(String[] args)throws Exception{
        if(args.length==2 && args[0].equals("synthetic")){
            synthetic(Paths.get(args[1]));
        }else if(args.length==3 && args[0].equals("real")){
            real(Paths.get(args[1]),Paths.get(args[2]));
        }else throw new IllegalArgumentException(
            "Usage: synthetic fixtureFolder OR real original.tar.gz appFilesDir");
    }
}
