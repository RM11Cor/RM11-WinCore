package org.kernix.host;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Single fixed MIT-only G2-D cross-DSO original-FEX Android guest child.
 * GATED BY caller's signed-BuildConfig qualified runner SHA256. Neither
 * a random local .so nor user-provided EXE, Wine or external guest is
 * permitted. The child independently validates its three exact x86-64
 * ELF hashes and anonymous snapshot bytes before executing any guest.
 *
 * This class is dormant in v0.21 and user-proven v0.22; it is enabled only by a separately qualified v0.23 G2-D signed package.
 */
final class G2DMitImportAndroidSupervisor {
    static final String RUNNER="libkernix_g2d_mit_import_candidate.so";
    static final String CORE="libFEXCore.so";
    static final String FLAG="--kernix-g2d-mit-pinned-pltrel-external-dso-v1";
    static final String REQUIRED_FEXCORE_SHA256 =
        "f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d";
    static final String GATE_CLOSED =
        "KERNIX_G2D_MIT_IMPORT_SIGNED_RUNNER_GATE_CLOSED_NOT_ANDROID_DEVICE_EXECUTED";

    private G2DMitImportAndroidSupervisor() {}

    private static File exactLibrary(File apkNativeDir,String name)
            throws IOException {
        if(apkNativeDir==null || !(RUNNER.equals(name) || CORE.equals(name)))
            throw new IOException("Not original signed native library");
        Path root=apkNativeDir.toPath().toRealPath();
        if(Files.isSymbolicLink(root) || !Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Signed native path redirected");
        Path path=root.resolve(name);
        if(Files.isSymbolicLink(path) || !Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) ||
           !path.toRealPath().getParent().equals(root))
            throw new IOException("Fixed native runner missing or redirected");
        return path.toFile().getCanonicalFile();
    }
    private static String sha256(Path path)throws IOException {
        MessageDigest hash;
        try {hash=MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException error){throw new IOException("SHA256 unavailable",error);}
        try(InputStream in=Files.newInputStream(path)) {
            byte[] buf=new byte[8192];
            int n;
            while((n=in.read(buf))!=-1)hash.update(buf,0,n);
        }
        StringBuilder out=new StringBuilder(64);
        for(byte value:hash.digest()) {
            out.append(Character.forDigit((value & 0xff)>>>4,16));
            out.append(Character.forDigit(value & 15,16));
        }
        return out.toString();
    }

    static String run(File appFilesDir,File apkNativeDir,String authorizedRunnerSHA256) {
        // Qualifier is injected ONLY by a verified, persistently signed
        // Android v0.23 G2-D MIT-only package. The normal v0.21 value is EMPTY.
        if(authorizedRunnerSHA256==null ||
           !authorizedRunnerSHA256.matches("[0-9a-f]{64}"))
            return GATE_CLOSED;
        Process child=null;
        try {
            G2DMitImportGuestAssets.attestAppPrivate(appFilesDir);
            File runner=exactLibrary(apkNativeDir,RUNNER);
            File core=exactLibrary(apkNativeDir,CORE);
            if(!runner.canExecute() || !core.canRead() ||
               !authorizedRunnerSHA256.equals(sha256(runner.toPath())) ||
               !REQUIRED_FEXCORE_SHA256.equals(sha256(core.toPath())))
                throw new IOException("MIT-x86-external-import signed APK FEX runner/core digest rejected");
            ProcessBuilder childBuilder=new ProcessBuilder(
                runner.getAbsolutePath(),FLAG,appFilesDir.getCanonicalPath());
            childBuilder.directory(appFilesDir);
            childBuilder.environment().clear();
            childBuilder.environment().put("LD_LIBRARY_PATH",apkNativeDir.getCanonicalPath());
            child=childBuilder.start();
            return G2CAndroidChildSupervisor.superviseG2DMitImport(child);
        } catch(IOException | SecurityException error) {
            return "KERNIX_G2C_MIT16K_CHILD_BLOCKED: " +
                error.getClass().getSimpleName() + ": " + error.getMessage();
        } catch(InterruptedException error) {
            Thread.currentThread().interrupt();
            return "KERNIX_G2C_MIT16K_CHILD_INTERRUPTED";
        } finally {
            if(child!=null)child.destroyForcibly();
        }
    }
}
