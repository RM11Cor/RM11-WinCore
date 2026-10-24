package com.rm11.autocore.runtime;

import android.content.Context;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * RM11 4.0.3: stage actual xkeyboard-config required by upstream X.Org
 * (whose CmdEntryPoint.start() returns false for missing XKB_CONFIG_ROOT).
 *
 * Only creates app-private files/native-xorg-xkb-data. Never modifies the
 * Wine prefix, Android downloads, game files, or the prior Java X11 backend.
 */
public final class NativeXkbConfigProvisioner {
    public static final String ASSET="x11/xkb-data.zip";
    public static final String MANIFEST_ASSET="x11/xkb-data-manifest.json";
    private static final String DIR="native-xorg-xkb-data";
    private static final String MARKER=".rm11-v403-xkb-sha256";
    private static final String[] REQUIRED={
            "rules/evdev","keycodes/evdev","types/complete",
            "compat/complete","symbols/pc","symbols/us"
    };
    private static final int MAX_FILES=9000;
    private static final long MAX_BYTES=75L*1024*1024;

    private NativeXkbConfigProvisioner() {}

    public static File ensure(Context context) throws Exception {
        File root=new File(context.getFilesDir(),DIR).getCanonicalFile();
        if(!root.isDirectory() && !root.mkdirs())
            throw new IOException("RM11_V403_XKB_DIRECTORY_CREATE_FAILED");

        JSONObject manifest;
        try(InputStream in=context.getAssets().open(MANIFEST_ASSET)) {
            byte[] data=new byte[32768];
            int n=in.read(data);
            if(n<=0 || n==data.length)
                throw new IOException("RM11_V403_XKB_MANIFEST_INVALID");
            manifest=new JSONObject(new String(data,0,n,StandardCharsets.UTF_8));
        }
        String expected=manifest.getString("sha256");
        if(!expected.matches("[0-9a-f]{64}"))
            throw new IOException("RM11_V403_XKB_MANIFEST_DIGEST_INVALID");
        File marker=new File(root,MARKER);
        if(Files.isRegularFile(marker.toPath(),LinkOption.NOFOLLOW_LINKS)
                && marker.length()<=80
                && expected.equals(new String(Files.readAllBytes(marker.toPath()),
                        StandardCharsets.UTF_8).trim())
                && requiredReady(root))return root;

        // Validate signed-APK asset against the build-time provenance before
        // extracting. No network, no untrusted zip input from user storage.
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream input=context.getAssets().open(ASSET)) {
            byte[] buf=new byte[32768];
            int n;
            while((n=input.read(buf))!=-1)digest.update(buf,0,n);
        }
        StringBuilder actual=new StringBuilder(64);
        for(byte b:digest.digest())
            actual.append(String.format(java.util.Locale.ROOT,"%02x",b&0xff));
        if(!expected.equals(actual.toString()))
            throw new IOException("RM11_V403_XKB_ASSET_SHA256_MISMATCH");

        int files=0;
        long total=0;
        String parent=root.getCanonicalPath()+File.separator;
        try(ZipInputStream archive=new ZipInputStream(context.getAssets().open(ASSET))) {
            ZipEntry entry;
            byte[] buf=new byte[16384];
            while((entry=archive.getNextEntry())!=null) {
                String name=entry.getName();
                if(name==null || name.length()>260 || name.startsWith("/")
                        || name.contains("\\") || name.contains("\u0000"))
                    throw new IOException("RM11_V403_INVALID_XKB_ENTRY");
                File target=new File(root,name).getCanonicalFile();
                if(!target.getCanonicalPath().startsWith(parent))
                    throw new IOException("RM11_V403_XKB_PATH_TRAVERSAL_BLOCKED");
                if(entry.isDirectory()) {
                    if(!target.isDirectory() && !target.mkdirs())
                        throw new IOException("RM11_V403_XKB_SUBDIRECTORY_FAILED");
                } else {
                    if(++files>MAX_FILES)
                        throw new IOException("RM11_V403_XKB_TOO_MANY_FILES");
                    File folder=target.getParentFile();
                    if(!folder.isDirectory() && !folder.mkdirs())
                        throw new IOException("RM11_V403_XKB_PARENT_FAILED");
                    try(FileOutputStream out=new FileOutputStream(target,false)) {
                        int count;
                        while((count=archive.read(buf))!=-1) {
                            total+=count;
                            if(total>MAX_BYTES)
                                throw new IOException("RM11_V403_XKB_EXTRACT_BUDGET_EXCEEDED");
                            out.write(buf,0,count);
                        }
                    }
                }
                archive.closeEntry();
            }
        }
        if(files!=manifest.getInt("files") || total!=manifest.getLong("uncompressed_bytes"))
            throw new IOException("RM11_V403_XKB_CONTENT_COUNT_MISMATCH");
        if(!requiredReady(root))
            throw new IOException("RM11_V403_XKB_REQUIRED_RULES_NOT_PRESENT");
        try(FileOutputStream markerOut=new FileOutputStream(marker,false)) {
            markerOut.write((expected+"\n").getBytes(StandardCharsets.UTF_8));
            markerOut.getFD().sync();
        }
        return root;
    }

    private static boolean requiredReady(File root) {
        for(String name:REQUIRED) {
            File f=new File(root,name);
            if(!Files.isRegularFile(f.toPath(),LinkOption.NOFOLLOW_LINKS)
                    || f.length()<20)return false;
        }
        return true;
    }
}
