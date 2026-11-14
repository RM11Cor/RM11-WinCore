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
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
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
    public static final String PHASE_FILE = "r3d6-phases.txt";
    private static final long TIMEOUT_MS = 6000L;
    private static boolean libraryLoaded;
    private static native String nativeRun(byte[] wine, byte[] ldso,
        byte[] guestStack, long wineEntry, long ldsoEntry, long guestRsp,
        long sessionNonce, int traceFd, int progressFd);
    private static synchronized void loadNative() {
        if (!libraryLoaded) {
            System.loadLibrary("carx_r3d4_first_syscall");
            libraryLoaded = true;
        }
    }
    // Diagnostic-only breadcrumbs. Never count these as x86 instructions.
    private void phase(String stage) {
        try (FileOutputStream stream = new FileOutputStream(
                new File(getFilesDir(), PHASE_FILE), true)) {
            stream.write((stage + "\n").getBytes(StandardCharsets.UTF_8));
            stream.getFD().sync();
        } catch (Throwable ignored) { }
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
        // A fresh phase log is required to tie events to this one launch.
        try (FileOutputStream stream = new FileOutputStream(
                new File(getFilesDir(), PHASE_FILE), false)) {
            stream.write(("session=" + Long.toUnsignedString(nonce) + "\n")
                .getBytes(StandardCharsets.UTF_8));
            stream.getFD().sync();
        } catch (Throwable ignored) { }
        phase("J0_SERVICE_DISPATCHED");
        new Handler(Looper.getMainLooper()).postDelayed(() ->
            Process.killProcess(Process.myPid()), TIMEOUT_MS);
        new Thread(() -> {
            int rawFd = -1;
            int progressFd = -1;
            try {
                phase("J1_WORKER_STARTED");
                long nativePage = Os.sysconf(OsConstants._SC_PAGESIZE);
                if (nativePage != 4096) { phase("E_NATIVE_PAGE_SIZE_UNSUPPORTED"); return; }
                phase("J2_NATIVE_4K_PAGE_OK");
                Path files = getFilesDir().toPath().toRealPath();
                Path root = files.resolve(GuestRootfsInstaller.ROOTFS_NAME);
                if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                    phase("E_WINE_ROOTFS_MISSING"); return;
                }
                phase("J3_ROOTFS_PRESENT");
                WineLinuxProcessLaunchContract.Plan plan =
                    WineLinuxProcessLaunchContract.prepare(files, 4096,
                        Process.myUid(), Os.getgid());
                WineLinuxProcessLaunchContract.validate(plan,
                    Process.myUid(), Os.getgid());
                phase("J4_WINE_LINUX_ABI_STACK_VALIDATED");
                byte[] wine = WineX86HostMappingProbe.pinned(root,
                    "usr/lib/wine/wine64", WineGuestElfPreflight.WINE64_SHA256);
                phase("J5_WINE_SHA256_VERIFIED");
                byte[] ldso = WineX86HostMappingProbe.pinned(root,
                    "lib64/ld-linux-x86-64.so.2", WineGuestElfPreflight.LDSO_SHA256);
                phase("J6_LDSO_SHA256_VERIFIED");
                File evidence = new File(getFilesDir(), EVIDENCE_FILE);
                // Existing evidence is deleted by the parent before each start.
                ParcelFileDescriptor output = ParcelFileDescriptor.open(evidence,
                    ParcelFileDescriptor.MODE_CREATE |
                    ParcelFileDescriptor.MODE_TRUNCATE |
                    ParcelFileDescriptor.MODE_WRITE_ONLY);
                rawFd = output.detachFd();
                output.close();
                ParcelFileDescriptor progress = ParcelFileDescriptor.open(
                    new File(getFilesDir(), PHASE_FILE),
                    ParcelFileDescriptor.MODE_CREATE |
                    ParcelFileDescriptor.MODE_APPEND |
                    ParcelFileDescriptor.MODE_WRITE_ONLY);
                progressFd = progress.detachFd();
                progress.close();
                phase("J7_FDS_OPENED");
                loadNative();
                phase("J8_NATIVE_LIBRARY_LOADED");
                // On a genuine original FEX syscall, native writes evidence
                // and _exit()s THIS CHILD PROCESS. It cannot return "PASS".
                phase("J9_CALLING_NATIVE_RUN");
                String nativeResult = nativeRun(wine, ldso, plan.guestInitialStack,
                    plan.guestWineEntry, plan.guestLoaderEntry,
                    plan.stackRSP, nonce, rawFd, progressFd);
                // Returning from native is diagnostic failure (not a real syscall).
                phase("E_NATIVE_RETURN_" + (nativeResult == null ? "NULL" :
                    nativeResult.replaceAll("[^A-Z0-9_]", "_").substring(0,
                        Math.min(nativeResult.length(), 100))));
            } catch (Throwable t) {
                phase("E_JAVA_" + t.getClass().getSimpleName() +
                    "_" + String.valueOf(t.getMessage())
                        .replaceAll("[^A-Za-z0-9_]", "_")
                        .substring(0, Math.min(
                            String.valueOf(t.getMessage()).length(), 90)));
            } finally {
                if (rawFd >= 0) {
                    try { android.os.ParcelFileDescriptor.adoptFd(rawFd).close(); }
                    catch (Throwable ignored) {}
                }
                if (progressFd >= 0) {
                    try { android.os.ParcelFileDescriptor.adoptFd(progressFd).close(); }
                    catch (Throwable ignored) {}
                }
            }
        }, "R3D4-Wine-FEX-Worker").start();
        return START_NOT_STICKY;
    }
}
