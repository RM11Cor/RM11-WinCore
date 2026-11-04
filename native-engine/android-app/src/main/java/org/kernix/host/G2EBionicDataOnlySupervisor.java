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
 * KERNIX G2-E/B signed, consent-only data verification: this Android native
 * child must attest exactly three original Linux x86-64 ELF assets and
 * their immutable snapshots, without starting FEX or guest Linux/Wine.
 * Version v0.25 only; wrong native runner hash fails closed.
 */
final class G2EBionicDataOnlySupervisor {
    static final String RUNNER="libkernix_g2e_bionic_data_only_child.so";
    static final String FLAG="--kernix-g2e-pinned-glibc-data-only-v1";
    static final String GATE_CLOSED =
        "KERNIX_G2E_SIGNED_DATA_ONLY_RUNNER_GATE_CLOSED";

    private G2EBionicDataOnlySupervisor() {}

    private static File exactLibrary(File apkNativeDir,String name)
            throws IOException {
        if(apkNativeDir==null || !RUNNER.equals(name))
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
        // Android v0.25 G2-E/B data-only package. Older APKs cannot enable it.
        if(authorizedRunnerSHA256==null ||
           !authorizedRunnerSHA256.matches("[0-9a-f]{64}"))
            return GATE_CLOSED;
        Process child=null;
        try {
            G2EGuestGlibcAssets.attestAppPrivate(appFilesDir);
            File runner=exactLibrary(apkNativeDir,RUNNER);
            if(!runner.canExecute() ||
               !authorizedRunnerSHA256.equals(sha256(runner.toPath())))
                throw new IOException("G2-E signed data-only runner digest rejected");
            ProcessBuilder childBuilder=new ProcessBuilder(
                runner.getAbsolutePath(),appFilesDir.getCanonicalPath(),FLAG);
            childBuilder.directory(appFilesDir);
            childBuilder.environment().clear();
            childBuilder.environment().put("LD_LIBRARY_PATH",apkNativeDir.getCanonicalPath());
            child=childBuilder.start();
            return G2CAndroidChildSupervisor.superviseG2EDataOnly(child);
        } catch(IOException | SecurityException error) {
            return "KERNIX_G2E_DATA_ONLY_CHILD_BLOCKED: " +
                error.getClass().getSimpleName() + ": " + error.getMessage();
        } catch(InterruptedException error) {
            Thread.currentThread().interrupt();
            return "KERNIX_G2E_DATA_ONLY_CHILD_INTERRUPTED";
        } finally {
            if(child!=null)child.destroyForcibly();
        }
    }
}
