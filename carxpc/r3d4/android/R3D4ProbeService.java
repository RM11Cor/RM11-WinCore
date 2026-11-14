package com.r4.carxpc;

import android.app.Application;
import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/** R3D4: manual-only, dedicated-process probe. Never invoke on UI process.
 *  The parent activity inspects an exact 56-byte evidence record. This service
 *  will kill its OWN separate process after 6s even when native execution hangs.
 */
public final class R3D4ProbeService extends Service {
    public static final String PROCESS_NAME = "com.r4.carxpc:r3d3_probe";
    public static final String EVIDENCE_FILE = "r3d4-first-syscall.bin";
    private static final long TIMEOUT_MS = 6000L;
    private static boolean libraryLoaded;
    private static native String nativeRun(byte[] wine, byte[] ldso,
        byte[] guestStack, long wineEntry, long ldsoEntry, long guestRsp,
        long sessionNonce, int traceFd);
    private static synchronized void loadNative() {
        if (!libraryLoaded) {
            System.loadLibrary("carx_r3d4_first_syscall");
            libraryLoaded = true;
        }
    }
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent request, int flags, int startId) {
        // PID/UID and process-name gate. Never use android:isolatedProcess,
        // since source-pinned guest rootfs belongs to this app's private UID.
        if (!PROCESS_NAME.equals(Application.getProcessName())) {
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        final long nonce = request == null ? 0L :
            request.getLongExtra("r3d4_nonce", 0L);
        if (nonce <= 0) {
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        new Handler(Looper.getMainLooper()).postDelayed(() ->
            Process.killProcess(Process.myPid()), TIMEOUT_MS);
        new Thread(() -> {
            int rawFd = -1;
            try {
                long nativePage = Os.sysconf(OsConstants._SC_PAGESIZE);
                if (nativePage != 4096) return;
                Path files = getFilesDir().toPath().toRealPath();
                Path root = files.resolve(GuestRootfsInstaller.ROOTFS_NAME);
                if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return;
                WineLinuxProcessLaunchContract.Plan plan =
                    WineLinuxProcessLaunchContract.prepare(files, 4096,
                        Process.myUid(), Os.getgid());
                WineLinuxProcessLaunchContract.validate(plan,
                    Process.myUid(), Os.getgid());
                byte[] wine = WineX86HostMappingProbe.pinned(root,
                    "usr/lib/wine/wine64", WineGuestElfPreflight.WINE64_SHA256);
                byte[] ldso = WineX86HostMappingProbe.pinned(root,
                    "lib64/ld-linux-x86-64.so.2", WineGuestElfPreflight.LDSO_SHA256);
                File evidence = new File(getFilesDir(), EVIDENCE_FILE);
                // Existing evidence is deleted by the parent before each start.
                ParcelFileDescriptor output = ParcelFileDescriptor.open(evidence,
                    ParcelFileDescriptor.MODE_CREATE |
                    ParcelFileDescriptor.MODE_TRUNCATE |
                    ParcelFileDescriptor.MODE_WRITE_ONLY);
                rawFd = output.detachFd();
                output.close();
                loadNative();
                // On a genuine original FEX syscall, native writes evidence
                // and _exit()s THIS CHILD PROCESS. It cannot return "PASS".
                nativeRun(wine, ldso, plan.guestInitialStack,
                    plan.guestWineEntry, plan.guestLoaderEntry,
                    plan.stackRSP, nonce, rawFd);
            } catch (Throwable ignored) {
                // Parent will report NOT_OBSERVED; never fabricate success.
            } finally {
                if (rawFd >= 0) {
                    try { android.system.Os.close(
                        android.os.ParcelFileDescriptor.adoptFd(rawFd).getFileDescriptor()); }
                    catch (Throwable ignored) {}
                }
            }
        }, "R3D4-Wine-FEX-Worker").start();
        return START_NOT_STICKY;
    }
}
