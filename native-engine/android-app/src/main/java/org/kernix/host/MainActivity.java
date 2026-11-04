package org.kernix.host;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import java.io.InputStream;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Button;
import android.view.SurfaceView;
import android.view.SurfaceHolder;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * KERNIX-native proof app. This is NOT a Windows emulator yet.
 * It shows facts from the actual Android system Vulkan loader.
 */
public final class MainActivity extends Activity {
    private static native int[] nativeHostProbe();
    private static native String nativeGpuProbe();
    private static native String nativeSurfaceProbe(android.view.Surface surface);
    private static native String nativeSwapchainProbe(android.view.Surface surface);
    private TextView details;
    private TextView gameDetails;
    private TextView surfaceDetails;
    private TextView runtimeDetails;
    private TextView processDetails;
    private TextView fexCoreDetails;
    private TextView x86ExecutionDetails;
    private TextView x86SyscallDetails;
    private TextView x86WriteDetails;
    private TextView x86ElfDetails;
    private TextView x86ElfRwDetails;
    private TextView x86HeapDetails;
    private TextView g2HostDetails;
    private TextView g2PageDetails;
    private final ExecutorService x86SyscallWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService x86WriteWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService x86ElfWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService x86ElfRwWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService x86HeapWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService g2HostWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService g2PageWorker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean x86SyscallProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean x86WriteProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean x86ElfProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean x86ElfRwProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean x86HeapProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean g2HostProbeStarted = new AtomicBoolean(false);
    private final AtomicBoolean g2PageProbeStarted = new AtomicBoolean(false);
    private final ExecutorService x86ExecutionWorker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean fixedX86ProbeStarted = new AtomicBoolean(false);
    private final ExecutorService fexWorker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean fexCoreProbeStarted = new AtomicBoolean(false);
    private final ExecutorService processWorker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean nativeProcessProbeStarted = new AtomicBoolean(false);
    private final ExecutorService renderWorker = Executors.newSingleThreadExecutor();
    private final AtomicInteger surfaceGeneration = new AtomicInteger();
    private final AtomicBoolean gpuProbeStarted = new AtomicBoolean(false);
    private android.view.Surface currentNativeSurface;
    private static final int PICK_EXE = 702;
    private static final boolean NATIVE_AVAILABLE;
    private static final String NATIVE_ERROR;

    static {
        boolean loaded = false;
        String error = "";
        try {
            System.loadLibrary("kernix_host");
            System.loadLibrary("kernix_host_jni");
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            error = e.getMessage();
        }
        NATIVE_AVAILABLE = loaded;
        NATIVE_ERROR = error;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout main = new LinearLayout(this);
        main.setOrientation(LinearLayout.VERTICAL);
        main.setPadding(28, 40, 28, 28);
        main.setBackgroundColor(Color.rgb(12, 19, 30));
        TextView title = new TextView(this);
        title.setText("KERNIX");
        title.setTextSize(32);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        main.addView(title);
        TextView subtitle = new TextView(this);
        subtitle.setText("Independent ARM64 Host · Technical Preview");
        subtitle.setTextColor(0xffa1b7d1);
        subtitle.setTextSize(15);
        main.addView(subtitle);
        details = new TextView(this);
        details.setTextColor(Color.WHITE);
        details.setTextSize(15);
        details.setPadding(0, 24, 0, 24);
        main.addView(details);
        Button probe = new Button(this);
        probe.setText("Check native KERNIX host");
        probe.setOnClickListener(v -> refresh());
        main.addView(probe);
        Button prepareRuntime = new Button(this);
        prepareRuntime.setText("Prepare isolated Android runtime folders");
        prepareRuntime.setOnClickListener(v -> {
            try {
                RuntimeLayout.Layout layout = RuntimeLayout.prepare(getFilesDir());
                runtimeDetails.setText(layout.diagnostic());
            } catch (java.io.IOException error) {
                runtimeDetails.setText("Private runtime setup REJECTED: " + error.getMessage());
            }
        });
        main.addView(prepareRuntime);
        runtimeDetails = new TextView(this);
        runtimeDetails.setTextColor(0xffc8d9f0);
        runtimeDetails.setTextSize(13);
        runtimeDetails.setText("No Android runtime components installed. Prepare private folders to inspect.");
        main.addView(runtimeDetails);
        Button processProof = new Button(this);
        processProof.setText("Test Android-native ARM64 executable (bounded)");
        processDetails = new TextView(this);
        processDetails.setTextColor(0xffc8d9f0);
        processDetails.setTextSize(13);
        processDetails.setText("Separate Bionic process test: not started. Not FEX/Wine.");
        processProof.setOnClickListener(v -> {
            if (!nativeProcessProbeStarted.compareAndSet(false, true)) return;
            processProof.setEnabled(false);
            processDetails.setText("Testing APK-shipped native executable without root...");
            processWorker.execute(() -> {
                String report = NativeProcessProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        processDetails.setText(report);
                });
            });
        });
        main.addView(processProof);
        main.addView(processDetails);
        Button fexProof = new Button(this);
        fexProof.setText("Test genuine FEXCore Android library load (no games)");
        fexCoreDetails = new TextView(this);
        fexCoreDetails.setTextColor(0xffc8d9f0);
        fexCoreDetails.setTextSize(13);
        fexCoreDetails.setText("Signed-APK FEXCore native-loader proof: not started.");
        fexProof.setOnClickListener(v -> {
            if (!fexCoreProbeStarted.compareAndSet(false, true)) return;
            fexProof.setEnabled(false);
            fexCoreDetails.setText("Loading actual Android ARM64 FEXCore in isolated process...");
            fexWorker.execute(() -> {
                String report = FexCoreLoadProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        fexCoreDetails.setText(report);
                });
            });
        });
        main.addView(fexProof);
        main.addView(fexCoreDetails);
        Button fixedX86Guest = new Button(this);
        fixedX86Guest.setText("Run fixed x86-64 CPU instructions via FEXCore (no game)");
        x86ExecutionDetails = new TextView(this);
        x86ExecutionDetails.setTextColor(0xffc8d9f0);
        x86ExecutionDetails.setTextSize(13);
        x86ExecutionDetails.setText("Actual x86-64 RAX=49 guest test: not started.");
        fixedX86Guest.setOnClickListener(v -> {
            if (!fixedX86ProbeStarted.compareAndSet(false, true)) return;
            fixedX86Guest.setEnabled(false);
            x86ExecutionDetails.setText("Running signed-APK fixed x86-64 ALU proof in isolated process...");
            x86ExecutionWorker.execute(() -> {
                String report = FixedX86GuestProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        x86ExecutionDetails.setText(report);
                });
            });
        });
        main.addView(fixedX86Guest);
        main.addView(x86ExecutionDetails);
        Button fixedX86Syscall = new Button(this);
        fixedX86Syscall.setText("Test real x86-64 Linux getpid syscall bridge (no games)");
        x86SyscallDetails = new TextView(this);
        x86SyscallDetails.setTextColor(0xffc8d9f0);
        x86SyscallDetails.setTextSize(13);
        x86SyscallDetails.setText("Actual guest syscall 39 → Android process PID test: not started.");
        fixedX86Syscall.setOnClickListener(v -> {
            if (!x86SyscallProbeStarted.compareAndSet(false, true)) return;
            fixedX86Syscall.setEnabled(false);
            x86SyscallDetails.setText("Running fixed guest getpid syscall in isolated process...");
            x86SyscallWorker.execute(() -> {
                String report = FixedX86SyscallProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        x86SyscallDetails.setText(report);
                });
            });
        });
        main.addView(fixedX86Syscall);
        main.addView(x86SyscallDetails);
        Button fixedX86Memory = new Button(this);
        fixedX86Memory.setText("Test x86 guest memory + write/getpid syscalls (v0.9)");
        x86WriteDetails = new TextView(this);
        x86WriteDetails.setTextColor(0xffc8d9f0);
        x86WriteDetails.setTextSize(13);
        x86WriteDetails.setText("Fixed x86-64 guest-memory pointer + two system calls: not tested on device.");
        fixedX86Memory.setOnClickListener(v -> {
            if (!x86WriteProbeStarted.compareAndSet(false, true)) return;
            fixedX86Memory.setEnabled(false);
            x86WriteDetails.setText("Running genuine x86-64 guest pointer/write + getpid through FEXCore...");
            x86WriteWorker.execute(() -> {
                String report = FixedX86WriteProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        x86WriteDetails.setText(report);
                });
            });
        });
        main.addView(fixedX86Memory);
        main.addView(x86WriteDetails);
        Button realX86Elf = new Button(this);
        realX86Elf.setText("Run genuine compiled x86-64 ELF64 via FEXCore (v0.10)");
        x86ElfDetails = new TextView(this);
        x86ElfDetails.setTextColor(0xffc8d9f0);
        x86ElfDetails.setTextSize(13);
        x86ElfDetails.setText("An independent x86-64 ELF64 PIE guest has not yet been tested on this Android device.");
        realX86Elf.setOnClickListener(v -> {
            if (!x86ElfProbeStarted.compareAndSet(false, true)) return;
            realX86Elf.setEnabled(false);
            x86ElfDetails.setText("Validating real ELF64 PT_LOAD segments and executing native FEXCore guest...");
            x86ElfWorker.execute(() -> {
                String report = FixedX86ElfProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        x86ElfDetails.setText(report);
                });
            });
        });
        main.addView(realX86Elf);
        main.addView(x86ElfDetails);
        Button elfRwMemory = new Button(this);
        elfRwMemory.setText("Run real x86 ELF64 .rodata → .data memory copy (v0.11)");
        x86ElfRwDetails = new TextView(this);
        x86ElfRwDetails.setTextColor(0xffc8d9f0);
        x86ElfRwDetails.setTextSize(13);
        x86ElfRwDetails.setText("Real ELF64 x86 writable-memory copy has not been tested on device.");
        elfRwMemory.setOnClickListener(v -> {
            if (!x86ElfRwProbeStarted.compareAndSet(false, true)) return;
            elfRwMemory.setEnabled(false);
            x86ElfRwDetails.setText("Running compiled ELF64 x86 REP MOVSB into guest .data via FEXCore...");
            x86ElfRwWorker.execute(() -> {
                String report = FixedX86ElfRwProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed()) x86ElfRwDetails.setText(report);
                });
            });
        });
        main.addView(elfRwMemory);
        main.addView(x86ElfRwDetails);
        Button elfManagedHeap = new Button(this);
        elfManagedHeap.setText("Verify original FEXCore x86 syscall ABI (G1 v0.19)");
        x86HeapDetails = new TextView(this);
        x86HeapDetails.setTextColor(0xffc8d9f0);
        x86HeapDetails.setTextSize(13);
        x86HeapDetails.setText("G1 proved x86-64 host mode must be set after FEX config reload. This v0.19 test runs original FEXCore and a matching guest fixture; Android execution is not verified yet.");
        elfManagedHeap.setOnClickListener(v -> {
            if (!x86HeapProbeStarted.compareAndSet(false, true)) return;
            elfManagedHeap.setEnabled(false);
            x86HeapDetails.setText("Testing corrected x86-64 mode with original FEXCore and real guest syscall values; no synthetic register values or games...");
            x86HeapWorker.execute(() -> {
                String report = FixedX86HeapProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed()) x86HeapDetails.setText(report);
                });
            });
        });
        main.addView(elfManagedHeap);
        main.addView(x86HeapDetails);
        // G2 is a separate Android-host diagnostic, not Wine execution.
        Button g2Button = new Button(this);
        g2Button.setText("Check G2 Bionic + FEX host boundary (no Windows games)");
        g2HostDetails = new TextView(this);
        g2HostDetails.setTextColor(0xffc8d9f0);
        g2HostDetails.setTextSize(13);
        g2HostDetails.setText("G2 sandbox, page size, FEX library load: not started.");
        g2Button.setOnClickListener(v -> {
            if (!g2HostProbeStarted.compareAndSet(false, true)) return;
            g2Button.setEnabled(false);
            g2HostDetails.setText("Checking real Bionic host process in isolated child...");
            g2HostWorker.execute(() -> {
                String report = G2HostBoundaryProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed()) g2HostDetails.setText(report);
                });
            });
        });
        main.addView(g2Button);
        main.addView(g2HostDetails);
        // G2-C native child is packaged as a fixed Android/Bionic PIE by CI.
        // This page/guard check is NOT guest FEX execution and reads no x86
        // files: a safe separate-process Android 4K/16K readiness witness.
        Button g2PageButton = new Button(this);
        g2PageButton.setText("G2-C: test Android memory pages (safe, no FEX)");
        g2PageDetails = new TextView(this);
        g2PageDetails.setTextColor(0xffc8d9f0);
        g2PageDetails.setTextSize(13);
        g2PageDetails.setText("G2-C native Android child: not tested on this device. No x86 or Wine.");
        g2PageButton.setOnClickListener(v -> {
            if (!g2PageProbeStarted.compareAndSet(false,true)) return;
            g2PageButton.setEnabled(false);
            g2PageDetails.setText("Checking signed-APK G2-C Bionic child and 4K/16K memory guards...");
            g2PageWorker.execute(() -> {
                final String report=G2CAndroidPageProbe.run(
                    new java.io.File(getApplicationInfo().nativeLibraryDir));
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed())
                        g2PageDetails.setText(report);
                });
            });
        });
        main.addView(g2PageButton);
        main.addView(g2PageDetails);
        Button gpuButton = new Button(this);
        gpuButton.setText("Enumerate real Vulkan GPU");
        gpuButton.setOnClickListener(v -> {
            if (!NATIVE_AVAILABLE) {
                details.setText("Native host unavailable: " + NATIVE_ERROR);
                return;
            }
            try {
                details.setText(nativeGpuProbe());
            } catch (Throwable e) {
                details.setText("GPU enumeration failed: " + e.getClass().getSimpleName());
            }
        });
        main.addView(gpuButton);
        SurfaceView nativeSurface = new SurfaceView(this);
        nativeSurface.setLayoutParams(new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 180));
        main.addView(nativeSurface);
        surfaceDetails = new TextView(this);
        surfaceDetails.setTextColor(Color.WHITE);
        surfaceDetails.setText("Android Vulkan window: not probed");
        main.addView(surfaceDetails);
        nativeSurface.getHolder().addCallback(new SurfaceHolder.Callback() {
            @Override public void surfaceCreated(SurfaceHolder holder) {
                currentNativeSurface = holder.getSurface();
                surfaceGeneration.incrementAndGet();
                surfaceDetails.setText("Vulkan surface ready. GPU test requires explicit action.");
            }
            @Override public void surfaceChanged(SurfaceHolder holder, int format,
                                                 int width, int height) {
                currentNativeSurface = holder.getSurface();
                surfaceGeneration.incrementAndGet();
                surfaceDetails.setText("Surface resized. Previous GPU report invalidated.");
            }
            @Override public void surfaceDestroyed(SurfaceHolder holder) {
                surfaceGeneration.incrementAndGet();
                currentNativeSurface = null;
                surfaceDetails.setText("Surface destroyed; stale reports discarded");
            }
        });
        Button runFrameTest = new Button(this);
        runFrameTest.setText("Run one bounded Vulkan frame test (optional)");
        runFrameTest.setOnClickListener(v -> {
            android.view.Surface active = currentNativeSurface;
            if (active == null || !active.isValid()) {
                surfaceDetails.setText("Surface unavailable; GPU test not started");
                return;
            }
            if (!gpuProbeStarted.compareAndSet(false, true)) {
                surfaceDetails.setText("GPU test already started in this app session.");
                return;
            }
            runFrameTest.setEnabled(false);
            scheduleSurfaceRender(active);
        });
        main.addView(runFrameTest);
        Button choose = new Button(this);
        choose.setText("Inspect Windows EXE (read-only)");
        choose.setOnClickListener(v -> {
            Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            picker.setType("*/*");
            picker.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(picker, PICK_EXE);
        });
        main.addView(choose);
        gameDetails = new TextView(this);
        gameDetails.setTextColor(Color.WHITE);
        gameDetails.setTextSize(15);
        gameDetails.setPadding(0, 14, 0, 16);
        gameDetails.setText("No EXE inspected. Only static PE metadata will be read.");
        main.addView(gameDetails);
        TextView warning = new TextView(this);
        warning.setText("Host preview only. Android-compatible FEX/Wine and games are not integrated. The bounded Vulkan probe is separate from Windows rendering.");
        warning.setTextColor(0xffffc77c);
        warning.setPadding(0, 20, 0, 0);
        main.addView(warning);
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(main);
        setContentView(scroll);
        refresh();
    }

    /**
     * All native Vulkan calls run off the UI thread. A resize invalidates the
     * previous report; queued tasks check generation and Surface validity.
     * The native call has up to four attempted frames and one swapchain
     * recreation. It can still stall in a defective GPU driver: testing
     * requires explicit user action and is capped at one run per session.
     */
    private void scheduleSurfaceRender(android.view.Surface surface) {
        if (!NATIVE_AVAILABLE || surface == null || !surface.isValid()) return;
        final int generation = surfaceGeneration.incrementAndGet();
        surfaceDetails.setText("Vulkan Surface: native frame sequence scheduled");
        renderWorker.execute(() -> {
            if (generation != surfaceGeneration.get() || !surface.isValid())
                return;
            String message;
            try {
                String surfaceReport = nativeSurfaceProbe(surface);
                if (generation != surfaceGeneration.get() || !surface.isValid())
                    return;
                String swapchainReport = nativeSwapchainProbe(surface);
                message = surfaceReport + "\n\n" + swapchainReport;
            } catch (Throwable error) {
                message = "Native Vulkan sequence failed: "
                        + error.getClass().getSimpleName();
            }
            final String result = message;
            runOnUiThread(() -> {
                if (generation == surfaceGeneration.get() && !isFinishing()
                        && !isDestroyed() && surfaceDetails != null)
                    surfaceDetails.setText(result);
            });
        });
    }

    @Override protected void onPause() {
        surfaceGeneration.incrementAndGet();
        super.onPause();
    }

    @Override protected void onDestroy() {
        surfaceGeneration.incrementAndGet();
        currentNativeSurface = null;
        renderWorker.shutdownNow();
        processWorker.shutdownNow();
        fexWorker.shutdownNow();
        x86ExecutionWorker.shutdownNow();
        x86SyscallWorker.shutdownNow();
        x86WriteWorker.shutdownNow();
        x86ElfWorker.shutdownNow();
        x86ElfRwWorker.shutdownNow();
        x86HeapWorker.shutdownNow();
        g2HostWorker.shutdownNow();
        super.onDestroy();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_EXE || resultCode != RESULT_OK || data == null) return;
        Uri selected = data.getData();
        if (selected == null) return;
        try (InputStream stream = getContentResolver().openInputStream(selected)) {
            gameDetails.setText(GameInspector.inspect(stream));
        } catch (Exception e) {
            gameDetails.setText("Unable to inspect EXE: " + e.getMessage());
        }
    }

    private void refresh() {
        if (!NATIVE_AVAILABLE) {
            details.setText("Native host unavailable: " + NATIVE_ERROR);
            return;
        }
        try {
            int[] report = nativeHostProbe();
            if (report == null || report.length != 5 || report[0] != 1 || report[1] != 1 || report[4] != 16) {
                details.setText("Host ABI mismatch or invalid response");
                return;
            }
            int flags = report[2];
            int v = report[3];
            String version = ((v >> 22) & 0x7f) + "." + ((v >> 12) & 0x3ff) + "." + (v & 0xfff);
            details.setText("Host ABI: " + report[0] + "\n"
                    + "Android ARM64: " + ((flags & 1) != 0 ? "reported" : "unavailable") + "\n"
                    + "Vulkan system loader: " + ((flags & 2) != 0 ? "loaded" : "not found") + "\n"
                    + "Vulkan version query: " + ((flags & 4) != 0 ? version : "not available") + "\n"
                    + "Vulkan API 1.1+: " + ((flags & 8) != 0 ? "loader reports yes" : "not confirmed") + "\n"
                    + "GPU/swapchain/game validation: NOT TESTED");
        } catch (Throwable e) {
            details.setText("Native host failed to load or run: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
    }
}
