package com.rm11.autocore.runtime;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class ImageFsProvisionerTest {
    private static void check(boolean b, String msg) { if (!b) throw new AssertionError(msg); }
    private static void file(Path p, String s) throws Exception {
        Files.createDirectories(p.getParent()); Files.write(p, s.getBytes(StandardCharsets.UTF_8));
    }
    private static byte[] zip(boolean includeSystem) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(o)) {
            String[] entries = includeSystem ? new String[]{"system.reg", "user.reg", "drive_c/windows/system32/ntdll.dll", "dosdevices/", "_rm11_symlinks.tsv"}
                : new String[]{"user.reg", "drive_c/windows/system32/ntdll.dll", "dosdevices/", "_rm11_symlinks.tsv"};
            for (String n : entries) {
                z.putNextEntry(new ZipEntry(n));
                if (n.equals("_rm11_symlinks.tsv")) {
                    String a=Base64.getEncoder().encodeToString("dosdevices/c:".getBytes(StandardCharsets.UTF_8));
                    String b=Base64.getEncoder().encodeToString("../drive_c".getBytes(StandardCharsets.UTF_8));
                    String c=Base64.getEncoder().encodeToString("dosdevices/z:".getBytes(StandardCharsets.UTF_8));
                    String d=Base64.getEncoder().encodeToString("/".getBytes(StandardCharsets.UTF_8));
                    z.write((a+"\t"+b+"\n"+c+"\t"+d+"\n").getBytes(StandardCharsets.UTF_8));
                } else if (!n.endsWith("/")) z.write("123".getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return o.toByteArray();
    }
    private static RuntimeLayout setup(Path base) throws Exception {
        Path runtime=base.resolve("runtime-v2417");
        for (String name: new String[]{"bin/wine", "bin/wineserver", "lib/wine/aarch64-unix/ntdll.so", "lib/wine/aarch64-windows/libarm64ecfex.dll", "lib/wine/aarch64-windows/libwow64fex.dll", "share/wine/nls/l_intl.nls", "prefixPack.txz"}) file(runtime.resolve(name), "runtime");
        file(runtime.resolve(".ready"), "v2.4.24\n");
        Path nativeDir=base.resolve("apk-native");
        file(nativeDir.resolve("libwineprobe.so"), "launcher"); file(nativeDir.resolve("libwineserverrm11.so"), "server");
        return new RuntimeLayout(base,nativeDir);
    }
    public static void main(String[] args) throws Exception {
        Path temp=Files.createTempDirectory("rm11-v251-");
        RuntimeLayout l=setup(temp);
        try {
            ImageFsProvisioner.provision(l,new ByteArrayInputStream(zip(true)));
            check(Files.isSymbolicLink(l.wineRoot),"Wine root must be a symlink to avoid 1 GB duplicate");
            check(Files.isRegularFile(l.winePrefixMarker()),"Prefix must be atomic and marked");
            check(Files.isSymbolicLink(l.winePrefix.resolve("dosdevices/c:")),"C: symlink preserved");
            check(Files.readSymbolicLink(l.winePrefix.resolve("dosdevices/z:")).toString().equals("/"),"Z: root restored");
            check(RuntimeAssessment.inspect(l).state()==RuntimeAssessment.State.BLOCKED,"Synthetic fake native ELF should fail readiness");
            String result=ImageFsProvisioner.provision(l,new ByteArrayInputStream(zip(true)));
            check(result.contains("preserved"),"Reentry must preserve prefix");
        } finally {}
        RuntimeLayout m=setup(Files.createTempDirectory("rm11-v251-incomplete-"));
        boolean threw=false;
        try {ImageFsProvisioner.provision(m,new ByteArrayInputStream(zip(false)));}catch(IOException e){threw=true;}
        check(threw,"Missing registry must fail closed");
        check(!Files.exists(m.winePrefix),"Incomplete prefix must not be published");
        check(Files.exists(m.winePrefix.resolveSibling(".wine.rm11-staging")),"Partial staging retained for audit");
        System.out.println("PASS: ImageFs symlink migration, prefix hardening, idempotency, path validation, preservation");
    }
}

