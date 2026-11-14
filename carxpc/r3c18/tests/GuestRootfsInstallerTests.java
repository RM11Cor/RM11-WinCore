package com.r4.carxpc;

import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public final class GuestRootfsInstallerTests {
    static final String[] REJECT={
       "traversal","absolute","drive_path","dot_component","duplicate",
       "missing_required","symlink_escape","hardlink_escape",
       "hardlink_symlink","special_outside_dev","checksum_bad"
    };
    static String sha256(Path f)throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(f)){
           byte[] b=new byte[65536];int n;
           while((n=in.read(b))>=0) if(n>0)sha.update(b,0,n);
        }
        StringBuilder s=new StringBuilder();
        for(byte b:sha.digest())s.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    static GuestRootfsInstaller.Receipt install(Path artifact,Path parent)
            throws Exception {
        try(InputStream in=Files.newInputStream(artifact)) {
            return GuestRootfsInstaller.installFixtureForUnitTest(
                in,parent,sha256(artifact));
        }
    }
    static void ensure(boolean ok,String msg){
        if(!ok)throw new AssertionError(msg);
    }
    static int stages(Path parent)throws IOException {
        try(java.util.stream.Stream<Path> files=Files.list(parent)) {
            return (int)files.filter(x->x.getFileName().toString()
                      .contains("-stage-")).count();
        }
    }
    public static void main(String[] args)throws Exception {
        ensure(args.length==1,"test fixture directory required");
        Path f=java.nio.file.Paths.get(args[0]);
        Path sandbox=Files.createTempDirectory("r3c18-rootfs-install-tests-");
        String receipt="";
        int count=0;
        try{
            Path good=f.resolve("good.tar.gz");
            GuestRootfsInstaller.Receipt r=install(good,sandbox);
            ensure(r.sha256.equals(sha256(good)),"GOOD_SHA_MISMATCH");
            ensure(r.root.equals(sandbox.resolve(GuestRootfsInstaller.ROOTFS_NAME)),"ROOT_DIR_WRONG");
            ensure(r.entries>=6 && r.symlinks==1 && r.hardlinks==1,"GOOD_ENTRY_COUNT_BAD");
            ensure(Files.isRegularFile(r.root.resolve("usr/share/wine/wine.inf")),"NO_WINE_INF");
            ensure(Files.isExecutable(r.root.resolve("usr/lib/wine/wine64")),"GUEST_WINE_NOT_EXECUTABLE");
            ensure(Files.isSymbolicLink(r.root.resolve("usr/bin/wine")),"MISSING_GUEST_SYMLINK");
            ensure(Files.isSameFile(r.root.resolve("usr/bin/wine"),r.root.resolve("usr/lib/wine/wine64")),
                   "RELATIVE_GUEST_WINE_LINK_BAD");
            ensure(Files.isSameFile(r.root.resolve("usr/bin/wine64"),r.root.resolve("usr/lib/wine/wine64")),
                   "GUEST_HARDLINK_BAD");
            ensure(!Files.exists(r.root.resolve("dev/null"),LinkOption.NOFOLLOW_LINKS),
                   "SPECIAL_DEVICE_WRONGLY_CREATED");
            receipt=new String(Files.readAllBytes(r.root.resolve(".r4-rootfs-receipt")),
                               java.nio.charset.StandardCharsets.UTF_8);
            ensure(receipt.contains("source_archive_sha256="+r.sha256),"RECEIPT_INVALID");
            ++count;

            // A real production call must reject even a valid small TAR
            // unless its bytes are exactly the source-pinned 515 MB rootfs.
            boolean prodRejected=false;
            try(InputStream in=Files.newInputStream(good)){
                GuestRootfsInstaller.install(in,sandbox);
            }catch(IOException e){prodRejected=e.getMessage().contains("ARCHIVE_SHA256_MISMATCH");}
            ensure(prodRejected,"PRODUCTION_ARCHIVE_PIN_BYPASS");
            ensure(stages(sandbox)==0,"STAGE_NOT_REMOVED_AFTER_DIGEST_FAILURE");
            ++count;

            for(String name:REJECT){
                boolean rejected=false;
                try{
                    install(f.resolve(name+".tar.gz"),sandbox);
                }catch(IOException e){rejected=true;}
                ensure(rejected,"MALICIOUS_TAR_ACCEPTED:"+name);
                ensure(stages(sandbox)==0,"PARTIAL_STAGE_LEAKED:"+name);
                ensure(Files.readAllBytes(r.root.resolve(".r4-rootfs-receipt")).length==receipt.getBytes("UTF-8").length,
                       "EXISTING_VALID_ROOTFS_MODIFIED:"+name);
                ensure(!Files.exists(sandbox.resolve("escape")) &&
                       !Files.exists(sandbox.resolve("outside")),"TAR_PATH_ESCAPED:"+name);
                ++count;
            }

            // Absolute guest symlink /usr/... is rewritten to a path
            // relative to the owned extracted guest root; never points at
            // host OS /usr.
            Path a=f.resolve("symlink_absolute_inside.tar.gz");
            GuestRootfsInstaller.Receipt abs=install(a,sandbox);
            ensure(Files.isSymbolicLink(abs.root.resolve("usr/bin/wine")),"ABS_LINK_NOT_CREATED");
            ensure(Files.isSameFile(abs.root.resolve("usr/bin/wine"),
                                    abs.root.resolve("usr/lib/wine/wine64")),"ABS_LINK_ESCAPED_GUEST_ROOT");
            ++count;
            ensure(stages(sandbox)==0,"STAGING_LEFTOVER");
            System.out.println(
                "CARX_R3C18_ROOTFS_INSTALLER_STREAMING_SHA256_ROLLBACK_"+
                count+"_UNIT_CASES_PASS_NO_ANDROID_WINE_EXECUTION");
        } finally {
            if(Files.exists(sandbox))try(java.util.stream.Stream<Path> stream=Files.walk(sandbox)) {
               List<Path> all=new ArrayList<>();stream.forEach(all::add);
               for(int i=all.size()-1;i>=0;i--)Files.deleteIfExists(all.get(i));
            }
        }
    }
}
