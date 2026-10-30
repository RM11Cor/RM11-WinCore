package com.rm11.autocore.runtime;

import android.content.Context;
import com.rm11.autocore.diagnostics.OfflineDiagnosticJournal;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Set;
import java.nio.file.attribute.PosixFilePermission;

/**
 * v49057: ACTUAL installed winebus.so deployment from a source-built, SHA-pinned
 * Bionic ELF in the signed APK. The previous experiments bundled an SDL device
 * but did not replace the Winebus runtime that wine services really load.
 *
 * Only an exact historical source-verified baseline (or our installed ELF) is
 * allowed. Preserve user's Wine prefix and games. No root or keyboard input.
 */
public final class NativeWineHidInstallerV49057 {
    private static final String BASELINE_SHA=
        "cca5501a884e504e1e414960ac69742938ecc4ba4a6a7e2685d818eb713f9f60";
    private static final String NEW_SHA=
        "42e9fefde6d579f76e734181fbcac7289cce7c71c5ef63374f49fb71f5d0aabe";
    private static final String ASSET="runtime/rm11-native-hid-winebus.so";
    private static final long MAX_BYTES=16L*1024L*1024L;

    private NativeWineHidInstallerV49057() {}

    private static String sha(Path path) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream input=Files.newInputStream(path)) {
            byte[] data=new byte[32768];
            for(int n;(n=input.read(data))!=-1;)digest.update(data,0,n);
        }
        StringBuilder out=new StringBuilder(64);
        for(byte value:digest.digest())
            out.append(String.format(java.util.Locale.ROOT,"%02x",value&0xff));
        return out.toString();
    }

    /**
     * Before wineserver is created, stage the attested Winebus ELF into the
     * actual runtime tree. Failed or foreign SHA leaves the original alone.
     * Avoid leaking sensitive absolute paths in the diagnostic event.
     */
    public static synchronized boolean prepare(Context context,RuntimeLayout layout) {
        Path original=layout.wineDllRoot.resolve("aarch64-unix/winebus.so");
        Path temporary=original.resolveSibling("winebus.so.rm11-hid-pending");
        Path baseline=original.resolveSibling("winebus.so.rm11-hid-baseline");
        String outcome="UNVERIFIED";
        try {
            Path trusted=layout.appFiles.toRealPath();
            Path parent=original.getParent().toRealPath();
            if(!parent.startsWith(trusted)
                    ||Files.isSymbolicLink(original)
                    ||!Files.isRegularFile(original,LinkOption.NOFOLLOW_LINKS)) {
                outcome="BLOCKED_FOREIGN_OR_MISSING_WINEBUS";
                return false;
            }
            if(Files.size(original)<65536 || Files.size(original)>MAX_BYTES) {
                outcome="BLOCKED_WINEBUS_SIZE";
                return false;
            }
            String existing=sha(original);
            if(NEW_SHA.equals(existing)) {
                outcome="READY_MATCHED_NATIVE_HID_ALREADY_INSTALLED";
                return true;
            }
            if(!BASELINE_SHA.equals(existing)) {
                outcome="BLOCKED_WINEBUS_BASELINE_SHA_MISMATCH";
                return false;
            }
            if(Files.isSymbolicLink(baseline)||Files.isSymbolicLink(temporary)) {
                outcome="BLOCKED_WINEBUS_BACKUP_SYMLINK";
                return false;
            }
            // Save the original baseline only once. The baseline is a Wine
            // shared object, not a user's game/prefix file.
            if(!Files.exists(baseline,LinkOption.NOFOLLOW_LINKS)) {
                Files.copy(original,baseline);
                if(!BASELINE_SHA.equals(sha(baseline))) {
                    Files.deleteIfExists(baseline);
                    outcome="BLOCKED_BASELINE_BACKUP_VERIFICATION";
                    return false;
                }
            }else if(!Files.isRegularFile(baseline,LinkOption.NOFOLLOW_LINKS)
                    ||!BASELINE_SHA.equals(sha(baseline))) {
                outcome="BLOCKED_EXISTING_BASELINE_BACKUP_UNVERIFIED";
                return false;
            }
            try(InputStream in=context.getAssets().open(ASSET);
                FileOutputStream out=new FileOutputStream(temporary.toFile())) {
                byte[] data=new byte[32768];
                long total=0;
                for(int n;(n=in.read(data))!=-1;){
                    total+=n;
                    if(total>MAX_BYTES)throw new IllegalStateException("NATIVE_HID_ASSET_TOO_LARGE");
                    out.write(data,0,n);
                }
                out.getFD().sync();
            }
            if(!NEW_SHA.equals(sha(temporary))) {
                outcome="BLOCKED_SIGNED_ASSET_SHA_MISMATCH";
                return false;
            }
            Set<PosixFilePermission> perms=
                    Files.getPosixFilePermissions(original,LinkOption.NOFOLLOW_LINKS);
            Files.setPosixFilePermissions(temporary,perms);
            Files.move(temporary,original,StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            if(!NEW_SHA.equals(sha(original))) {
                outcome="BLOCKED_POST_INSTALL_SHA_MISMATCH";
                return false;
            }
            outcome="READY_SOURCE_BUILT_WINEBUS_INSTALLED";
            return true;
        }catch(Exception failure) {
            outcome="BLOCKED_"+failure.getClass().getSimpleName();
            return false;
        }finally {
            try { Files.deleteIfExists(temporary); }catch(Exception ignored){}
            OfflineDiagnosticJournal.record(context,"v49057-native-winebus-install",
                    "RM11_V49057_INSTALL="+outcome+"\n"
                    +"RM11_V49057_EXPECTED_SOURCE_BUILD_SHA256="+NEW_SHA+"\n"
                    +"RM11_V49057_WINE_PREFIX_UNCHANGED=true\n"
                    +"RM11_V49057_ACTUAL_WINDOWS_ENUMERATION=UNVERIFIED_UNTIL_DEVICE");
        }
    }
}
