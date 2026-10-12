package com.rm11.wincore;

import android.content.Context;
import android.os.Build;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** V2.2.5 ONLY runs our own offline Windows console PE under Wine via Box64.
 * PASS requires BOTH a zero process status AND marker created through Win32 IO.
 * Not a user-file launcher or evidence that games/graphics are supported.
 */
public final class WineFirstExeV22 {
    private WineFirstExeV22() { }
    private static final String ASSET = "wine_exe_v22/";
    private static final String MARKER_FILE = "RM11-V22-WIN32-OK.txt";
    private static final String MARKER = "RM11_V22_WINDOWS_PE_EXEC_OK\n";
    private static final String WIN_DIR = "usr/lib/x86_64-linux-gnu/wine/x86_64-windows/";
    private static final String[] ESSENTIAL = {"kernel32.dll", "kernelbase.dll", "wineboot.exe", "services.exe", "explorer.exe", "winedevice.exe", "plugplay.exe", "rpcss.exe"};
    private static final int MAX_FILE = 128 * 1024 * 1024;
    // A Wine NLS manifest can contain up to 128 codepages plus PE modules.
    // 10,000 bytes rejected valid V2.2.1 manifests before Wine could start.
    static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    static final int MAX_LOG = 32000;
    /** Keeps the first 4 KB and final 28 KB instead of losing the fatal tail on chatty Box64 runs. */
    static final class HeadTailLog {
        private static final int HEAD = 4096;
        private static final int TAIL = MAX_LOG - HEAD;
        private final ByteArrayOutputStream first = new ByteArrayOutputStream(HEAD);
        private final byte[] last = new byte[TAIL];
        private long count;
        private int tailPos;

        synchronized void append(byte[] src, int length) {
            if (length < 0 || length > src.length) throw new IllegalArgumentException("Invalid log chunk");
            int f = Math.min(length, HEAD - first.size());
            if (f > 0) first.write(src, 0, f);
            for (int i = 0; i < length; ++i) {
                last[tailPos] = src[i];
                tailPos = (tailPos + 1) % TAIL;
            }
            count += length;
        }

        synchronized String text() {
            byte[] initial = first.toByteArray();
            int tailBytes = (int)Math.min(count, TAIL);
            int start = count >= TAIL ? tailPos : 0;
            byte[] suffix = new byte[tailBytes];
            for (int i = 0; i < tailBytes; ++i) suffix[i] = last[(start+i)%TAIL];
            if (count <= MAX_LOG) {
                int overlap = Math.max(0, initial.length + tailBytes - (int)count);
                return new String(initial, StandardCharsets.UTF_8)
                    + new String(suffix, overlap, tailBytes-overlap, StandardCharsets.UTF_8);
            }
            return new String(initial, StandardCharsets.UTF_8)
                + "\n[LOG TRUNCATED: middle omitted; crash tail preserved]\n"
                + new String(suffix, StandardCharsets.UTF_8);
        }
    }
    private static final String NLS_DIR = "usr/share/wine/nls/";
    private static final String[] NLS_REQUIRED = {"locale.nls","l_intl.nls","c_1252.nls","c_437.nls"};
    private static final int TIMEOUT_SECONDS = 55; // Win32 probe timeout; do not conflate with boot.
    private static final int BOOT_TIMEOUT_SECONDS = 120; // First-time Wine boot under ARM64 / Box64.

    // A first-time Wine prefix is initialized explicitly BEFORE the Win32 EXE probe.
    private static final String BOOT_REG = "system.reg";
    private static final String USER_REG = "user.reg";
    private static final String BOOT_RECEIPT = "rm11-v235-boot-ready.ok";

    /** Only records progress observed in the byte stream; it never treats a request as an IPC reply. */
    static final class BootTrace {
        private String carry = "";
        boolean bridge, serverStart, initFirstThread, socketEof, ctypeError;
        synchronized void observe(byte[] block, int count) {
            String incoming = carry + new String(block, 0, count, StandardCharsets.UTF_8);
            bridge |= incoming.contains("RM11_WINESERVER_BRIDGE_ENTERED");
            serverStart |= incoming.contains("wineserver: starting");
            initFirstThread |= incoming.contains("init_first_thread");
            socketEof |= incoming.contains("sock_init: shutdown() causes EOF");
            ctypeError |= incoming.contains("__ctype_b_loc not found") ||
                incoming.contains("__ctype_tolower_loc not found");
            carry = incoming.substring(Math.max(0, incoming.length() - 96));
        }
        synchronized String summary() {
            return "[IPC OBSERVATIONS] native_bridge=" + (bridge ? "YES" : "NO")
                + "; server_start_line=" + (serverStart ? "OBSERVED" : "NOT OBSERVED")
                + "; init_first_thread_request=" + (initFirstThread ? "YES" : "NOT OBSERVED")
                + "; socket_eof=" + (socketEof ? "YES" : "NOT OBSERVED")
                + "; ctype_errors=" + (ctypeError ? "YES" : "NOT OBSERVED")
                + "\n[IPC LIMIT] A request or server startup is NOT proof of a successful reply.\n";
        }
    }

    static Map<String,String> parseManifest(String text) {
        Map<String,String> result = new HashMap<>();
        for (String line : text.split("\\r?\\n")) {
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("Version: ") || line.startsWith("Use: ")) continue;
            String[] parts = line.split("\\t",-1);
            if (parts.length!=3 || !(parts[0].startsWith("usr/lib/x86_64-linux-gnu/wine/") ||
                parts[0].startsWith(NLS_DIR) || parts[0].equals("usr/share/wine/wine.inf")) ||
                parts[0].contains("..") || parts[0].contains("\\\\") ||
                !parts[1].matches("[0-9a-f]{64}") || !parts[2].matches("[0-9]{1,10}"))
                throw new IllegalArgumentException("Untrusted Wine PE manifest entry");
            if (result.put(parts[0],parts[1])!=null) throw new IllegalArgumentException("Duplicate Wine PE module");
        }
        if (result.size()<8 || result.size()>4096) throw new IllegalArgumentException("Invalid Wine PE module count");
        for (String module : ESSENTIAL) if (!result.containsKey(WIN_DIR+module))
            throw new IllegalArgumentException("Missing core Windows PE module: "+module);
        for (String name : NLS_REQUIRED) if (!result.containsKey(NLS_DIR+name))
            throw new IllegalArgumentException("Missing Wine NLS file: " + name);
        if (!result.containsKey("usr/share/wine/wine.inf"))
            throw new IllegalArgumentException("Missing Wine prefix configuration file");
        return result;
    }

    static String classify(int exitCode, boolean timeout, boolean markerOk, String log) {
        if (timeout) return "[TIMEOUT] Wine Windows EXE did not finish in " + TIMEOUT_SECONDS + " seconds.\n";
        if (exitCode==0 && markerOk) return "[PASS WINDOWS EXE] Verified own x86-64 PE invoked Win32 CreateFileA/WriteFile under Wine.\n"
          + "[LIMIT] Does NOT establish general EXE, GUI, DXVK, games or FPS compatibility.\n";
        String lower = log.toLowerCase(Locale.ROOT);
        // A fatal pointer-tag/allocator error takes priority over earlier
        // incidental missing-dependency warnings printed during Wine startup.
        if (lower.contains("rm11_wineserver_bridge_dependency_fail") || lower.contains("rm11_wineserver_bridge_exec_fail"))
            return "[WINESERVER BRIDGE ERROR] Native helper could not launch Box64 or Wine server.\n";
        if (lower.contains("pointer tag") || lower.contains("box64(free") || lower.contains("sigabrt"))
            return "[MEMORY CRASH] Native heap/Box64 pointer or Wine allocation fault suspected; tag opt-out is a TEMPORARY diagnostic, not an allocator fix.\n";
        if (lower.contains("unrecognized charset"))
            return "[LOCALE ABI] Box64 glibc/Bionic charset mapping still failed.\n";
        if (lower.contains("failed to load") && lower.contains(".nls"))
            return "[NLS BLOCKED] Wine failed to read its packaged locale data.\n";
        if (lower.contains("no such file") || lower.contains("could not load") || lower.contains("error loading needed")
                || lower.contains("unresolved") || lower.contains("symbol not found") || lower.contains("not found in lib")
                || lower.contains("failed to start") || lower.contains("could not be started")
                || lower.contains("exec format") || lower.contains("wineserver"))
            return "[BLOCKED] Wine initialization, wineserver, DLL or Box64 dependency failed. Read exact first error above.\n";
        if (exitCode==0) return "[NOT PROVEN] Process exited 0 but did NOT write Win32 marker. No EXE success claimed.\n";
        return "[FAIL WINDOWS EXE] Exit=" + exitCode + "; marker=" + markerOk + ". Read log above.\n";
    }

    // Limit reads even if a corrupt APK includes unusually large assets.
    static byte[] readAssetBounded(InputStream in, String path, int limit) throws Exception {
        if (limit < 1) throw new IllegalArgumentException("Invalid asset limit");
        try (InputStream stream = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] block = new byte[8192]; int n;
            while ((n=stream.read(block)) != -1) {
                if (n > limit - out.size()) throw new IllegalArgumentException("Oversized asset: " + path);
                out.write(block,0,n);
            }
            return out.toByteArray();
        }
    }
    private static byte[] asset(Context ctx, String path, int limit) throws Exception {
        return readAssetBounded(ctx.getAssets().open(path), path, limit);
    }
    static boolean prefixInitialized(File prefix) {
        return new File(prefix, BOOT_REG).isFile() && new File(prefix, USER_REG).isFile()
            && new File(prefix, BOOT_RECEIPT).isFile();
    }

    private static String sha(byte[] data) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb=new StringBuilder();
        for(byte b:digest) sb.append(String.format(Locale.ROOT,"%02x",b&255));
        return sb.toString();
    }
    private static void stage(File root, String rel, byte[] data) throws Exception {
        File target=new File(root,rel);
        if (!target.getParentFile().isDirectory() && !target.getParentFile().mkdirs())
            throw new IllegalStateException("Cannot create staging directories");
        try(FileOutputStream out = new FileOutputStream(target)) {out.write(data); out.getFD().sync();}
    }

    /** Stream a complete Wine asset to a private path and check its actual hash.
     * A manifest entry is not an execution guarantee or a glibc compatibility check. */
    private static void stageVerifiedAsset(Context ctx, File root, String assetName,
                                            String rel, String expected) throws Exception {
        File target = new File(root, rel);
        File parent = target.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs())
            throw new IllegalStateException("Cannot create Wine component directory: " + rel);
        File tmp = new File(parent, target.getName() + ".rm11-tmp");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (InputStream input = ctx.getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] b = new byte[64 * 1024]; int n;
            while ((n = input.read(b)) != -1) {
                total += n;
                if (total > MAX_FILE) throw new IllegalArgumentException("Wine asset oversized: " + rel);
                digest.update(b, 0, n);
                out.write(b, 0, n);
            }
            out.getFD().sync();
        } catch (Exception e) { tmp.delete(); throw e; }
        StringBuilder computed = new StringBuilder(64);
        for (byte b: digest.digest()) computed.append(String.format(Locale.ROOT, "%02x", b & 255));
        if (total < 32 || !expected.equals(computed.toString())) {
            tmp.delete();
            throw new IllegalArgumentException("Wine component missing or SHA256 mismatch: " + rel);
        }
        try { Files.move(tmp.toPath(), target.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING); }
        catch (Exception e) { tmp.delete(); throw e; }
    }

    /** Only a symlink into the APK's extracted nativeLibraryDir is executable.
     * Reject a pre-existing file or symlink pointing anywhere else.
     */
    static void installWineServerLink(File link, File trustedBridge) throws Exception {
        if (!trustedBridge.isFile() || !trustedBridge.canExecute())
            throw new IllegalStateException("Trusted wineserver native bridge absent");
        Path target = trustedBridge.getCanonicalFile().toPath();
        Path at = link.toPath();
        if (!link.getParentFile().isDirectory() && !link.getParentFile().mkdirs())
            throw new IllegalStateException("Wine bin directory missing");
        if (Files.isSymbolicLink(at)) {
            if (Files.readSymbolicLink(at).equals(target)) return;
            // Existing symlink must be replaced, not followed.
            Files.delete(at);
        } else if (Files.exists(at, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Unexpected non-symlink wineserver entry; refusing to overwrite");
        }
        Files.createSymbolicLink(at, target);
        if (!Files.isSymbolicLink(at) || !Files.readSymbolicLink(at).equals(target))
            throw new IllegalStateException("Failed to bind Wine wineserver executable");
    }

    private enum ProbeMode { NORMAL, REDUCED_TAG_CHECKS, MALLOC_TRACKING }

    public static String run(Context ctx) { return run(ctx, ProbeMode.NORMAL); }

    /** Dedicated offline phase one: real wineboot.exe --init under Box64. */
    public static String runBootstrap(Context ctx) { return run(ctx, ProbeMode.NORMAL, true); }

    /** Legacy opt-in A/B diagnostic; weakens Bionic checking ONLY in the Box64 subprocess. */
    public static String runHeapDiagnostic(Context ctx) { return run(ctx, ProbeMode.REDUCED_TAG_CHECKS); }

    /** New V2.2.5 probe: Box64 special malloc/mmap/free tracking; Android heap safety stays enabled. */
    public static String runMallocTrackingDiagnostic(Context ctx) { return run(ctx, ProbeMode.MALLOC_TRACKING); }

    private static String run(Context ctx, ProbeMode mode) { return run(ctx, mode, false); }

    private static String run(Context ctx, ProbeMode mode, boolean bootstrapOnly) {
        boolean isolateHeap = mode == ProbeMode.REDUCED_TAG_CHECKS;
        boolean mallocTracking = mode == ProbeMode.MALLOC_TRACKING;
        StringBuilder report = new StringBuilder("RM11 WinCore V2.3.5 / isolated Wine bootstrap trial\n")
            .append("RM11_SOURCE_V2_3_5\n")
            .append(bootstrapOnly ? "[PHASE] WINE_BOOT_ONLY\n" : "[PHASE] WIN32_EXE\n")
            .append("Offline, first-party Win32 CreateFileA/WriteFile test only; no game/GUI or external EXE.\n");
        if (Build.SUPPORTED_ABIS.length==0 || !"arm64-v8a".equals(Build.SUPPORTED_ABIS[0]))
            return report.append("[STOP] ARM64 device required.\n").toString();
        report.append(mallocTracking
            ? "[TRACKING TEST] BOX64_MALLOC_HACK=2 only for this Box64 child; Android heap tags stay enabled; NOT a fix.\n"
            : isolateHeap
                ? "[ISOLATED HEAP TEST] Reduced heap-tag protection ONLY in Box64 child process for this one run, NOT a fix.\n"
                : "[DEFAULT] Native heap pointer tagging stays enabled; baseline test.\n");
        File nativeDir=new File(ctx.getApplicationInfo().nativeLibraryDir);
        File box=new File(nativeDir,"librm11box64.so");
        File bridge=new File(nativeDir,"librm11wineserverbridge.so");
        if (!box.isFile() || !bridge.isFile())
            return report.append("[NOT BUILT] Box64 or wineserver ARM64 bridge missing in APK.\n").toString();
        Process process=null;
        try {
            File root=new File(ctx.getCacheDir(),"rm11-wine-v22");
            WineRuntimeV21.stageTo(ctx,root); // requires all SHA256-checked 7 Wine startup binaries
            String manifest=new String(asset(ctx,ASSET+"WINDOWS-COMPONENTS.tsv",MAX_MANIFEST_BYTES),StandardCharsets.UTF_8);
            Map<String,String> modules=parseManifest(manifest);
            // V2.3.5: every official x86-64 Wine PE/ELF module and data file
            // is packaged, instead of the arbitrary ~30-DLL allowlist that could
            // silently omit boot dependencies. Copy with bounded streaming SHA256
            // to avoid allocating hundreds of megabytes of byte[] on Android.
            int modulesStaged = 0;
            for (String rel : new java.util.TreeSet<>(modules.keySet())) {
                stageVerifiedAsset(ctx, root, ASSET + rel, rel, modules.get(rel));
                modulesStaged++;
                if (rel.startsWith("usr/share/wine/")) {
                    String alt = "share/wine/" + rel.substring("usr/share/wine/".length());
                    File altPath = new File(root, alt);
                    File canonicalPath = new File(root, rel);
                    if (!altPath.getParentFile().isDirectory() && !altPath.getParentFile().mkdirs())
                        throw new IllegalStateException("Cannot prepare Wine data fallback");
                    Files.copy(canonicalPath.toPath(), altPath.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            report.append("[COMPLETE WINE COMPONENT AUDIT] ").append(modulesStaged)
                .append(" matched package assets SHA256 verified; all packaged Wine modules, not a curated DLL allowlist.\n");
            byte[] exe=asset(ctx,ASSET+"rm11_probe.exe",100000);
            String expected=new String(asset(ctx,ASSET+"PE-SHA256.txt",128),StandardCharsets.UTF_8).trim();
            if (!expected.matches("[0-9a-f]{64}") || !sha(exe).equals(expected))
                throw new IllegalArgumentException("Windows test EXE SHA256 mismatch");
            // PE32+ x86-64 signature, import table names and literal test marker.
            int peOff = (exe[0x3c] & 255) | ((exe[0x3d] & 255) << 8) |
                        ((exe[0x3e] & 255) << 16) | ((exe[0x3f] & 255) << 24);
            if (exe.length<1024 || exe[0]!='M' || exe[1]!='Z' ||
                peOff<64 || peOff>exe.length-26 || exe[peOff]!='P' || exe[peOff+1]!='E' ||
                exe[peOff+2]!=0 || exe[peOff+3]!=0 ||
                (exe[peOff+4]&255)!=0x64 || (exe[peOff+5]&255)!=0x86 ||
                (exe[peOff+24]&255)!=0x0b || (exe[peOff+25]&255)!=0x02 ||
                !new String(exe,StandardCharsets.ISO_8859_1).contains("KERNEL32.dll") ||
                !new String(exe,StandardCharsets.ISO_8859_1).contains("CreateFileA"))
                throw new IllegalArgumentException("Not a recognized first-party Win64 PE");
            File work = new File(ctx.getFilesDir(),mallocTracking?"rm11-v225-malloc-tracking-work":isolateHeap?"rm11-v224-heap-isolation-work":"rm11-v235-win32-work");
            if (!work.isDirectory() && !work.mkdirs()) throw new IllegalStateException("Workdir unavailable");
            File success=new File(work,MARKER_FILE);
            if (success.exists() && !success.delete()) throw new IllegalStateException("Stale marker could not be removed");
            File guest=new File(work,"rm11_probe.exe");
            stage(work,"rm11_probe.exe",exe);
            File prefix=new File(ctx.getFilesDir(),mallocTracking?"rm11-v225-malloc-tracking-prefix":isolateHeap?"rm11-v224-heap-isolation-prefix":"rm11-v235-wineprefix");
            if (!prefix.isDirectory() && !prefix.mkdirs()) throw new IllegalStateException("Wine prefix unavailable");
            // Dedicated V2.3.5 sandbox. NEVER delete a user's existing Wine prefix.
            report.append("[GLIBC/BIONIC LIMIT] Ubuntu x86-64 Wine requires glibc ABI; "
                + "current Android/Bionic wrapper is not a validated full glibc userspace. "
                + "A full compatible runtime is required for a reliable engine.\n");
            report.append("[PREFIX V235] isolated from V2.3.3; initial state=")
                .append(prefixInitialized(prefix) ? "registry files found" : "not initialized").append('\n');
            // Only the successful V2.3.5 Wine-boot phase may authorize EXE.
            // Existing registry files by themselves are insufficient.
            File receipt = new File(prefix, BOOT_RECEIPT);
            if (bootstrapOnly && receipt.exists() && !receipt.delete())
                throw new IllegalStateException("Cannot reset boot success receipt");
            if (!bootstrapOnly && mode == ProbeMode.NORMAL && !prefixInitialized(prefix)) {
                return report.append("[EXE SKIPPED] This version requires Wine boot first. ")
                    .append("Press 'تهيئة Wine أولاً' in section 22, then retry the EXE only if [BOOT READY] appears.\n")
                    .toString();
            }
            String[] startup = {"wineboot.exe","services.exe","explorer.exe","winedevice.exe","plugplay.exe","rpcss.exe"};
            for (String entry : startup) {
                report.append("[WINE BOOT COMPONENT] ").append(entry).append(": ")
                    .append(modules.containsKey(WIN_DIR+entry)?"STAGED":"MISSING FROM APK")
                    .append('\n');
            }
            File wine=new File(root,"usr/lib/wine/wine64");
            File server=new File(root,"usr/lib/wine/wineserver64");
            if (!wine.canExecute() || !server.canExecute()) throw new IllegalArgumentException("Wine/wineserver executable missing");
            // Wine (Ubuntu 9.0) spawns <bindir>/wineserver even when the
            // WINESERVER variable points elsewhere. Make THAT expected name
            // resolve to our immutable APK native ARM64 executable.
            File wineServerEntry = new File(root, "usr/lib/wine/wineserver");
            installWineServerLink(wineServerEntry, bridge);
            report.append("[WINESERVER ENTRY] exact Wine spawn path -> verified APK native helper\n");
            // Verify the native helper can resolve both Box64 and wineserver64
            // before running any Win32 executable. No Wine child is started.
            // Redirect to a private regular file. A subprocess can otherwise leave
            // the inherited pipe open after the helper exits, making read-to-EOF
            // wait indefinitely even though waitFor(6s) already returned.
            File bridgeTrace = File.createTempFile("rm11-v235-bridge-", ".log", ctx.getCacheDir());
            String bridgeLog;
            int bridgeCode;
            try {
                ProcessBuilder checkBridge = new ProcessBuilder(bridge.getAbsolutePath(), "--rm11-self-test");
                checkBridge.redirectErrorStream(true);
                checkBridge.redirectOutput(bridgeTrace);
                checkBridge.environment().put("RM11_WINESERVER64_PATH", server.getAbsolutePath());
                Process bridgeProbe = checkBridge.start();
                boolean bridgeDone = bridgeProbe.waitFor(6,TimeUnit.SECONDS);
                if (!bridgeDone) {
                    bridgeProbe.destroyForcibly();
                    bridgeProbe.waitFor(2,TimeUnit.SECONDS);
                    report.append("[WINESERVER PREFLIGHT TIMEOUT] Native bridge did not exit\n");
                    return report.toString();
                }
                bridgeCode = bridgeProbe.exitValue();
                try (InputStream input = new java.io.FileInputStream(bridgeTrace)) {
                    bridgeLog = new String(readAssetBounded(input, "bridge preflight", 8192), StandardCharsets.UTF_8);
                }
            } finally {
                // Never preserve stale helper output across runs.
                bridgeTrace.delete();
            }
            if (bridgeCode != 0 || !bridgeLog.contains("RM11_WINESERVER_BRIDGE_PREFLIGHT_OK")) {
                report.append("[WINESERVER PREFLIGHT FAIL] exit=").append(bridgeCode).append(" ").append(bridgeLog).append('\n');
                return report.toString();
            }
            report.append("RM11_WINESERVER_BRIDGE_PREFLIGHT_OK\n");
            // Real execution diagnostic: unlike --rm11-self-test, this invokes
            // the actual x86-64 wineserver through the ARM64 bridge and Box64.
            // It does not claim that Wine IPC or prefix initialization works.
            File serverTrace = File.createTempFile("rm11-v235-server-", ".log", ctx.getCacheDir());
            try {
                ProcessBuilder serverCheck = new ProcessBuilder(bridge.getAbsolutePath(), "--version");
                serverCheck.redirectErrorStream(true);
                serverCheck.redirectOutput(serverTrace);
                serverCheck.environment().put("RM11_WINESERVER64_PATH", server.getAbsolutePath());
                Process serverProbe = serverCheck.start();
                boolean serverDone = serverProbe.waitFor(15, TimeUnit.SECONDS);
                if (!serverDone) {
                    serverProbe.destroyForcibly();
                    serverProbe.waitFor(2, TimeUnit.SECONDS);
                    report.append("[WINESERVER EXEC TIMEOUT] Real bridge -> Box64 -> wineserver --version stalled\n");
                    return report.toString();
                }
                int serverCode = serverProbe.exitValue();
                String serverOutput;
                try (InputStream input = new java.io.FileInputStream(serverTrace)) {
                    serverOutput = new String(readAssetBounded(input, "wineserver version", 8192), StandardCharsets.UTF_8);
                }
                report.append("[WINESERVER EXEC] exit=").append(serverCode).append(" output=")
                    .append(serverOutput).append('\n');
                if (serverCode != 0) {
                    report.append("[BOOT BLOCKED] Actual wineserver cannot start; no wineboot attempted\n");
                    return report.toString();
                }
            } finally {
                serverTrace.delete();
            }

            report.append("[STAGED] 7 V2.1 Wine binaries + ").append(modules.size()).append(" Wine PE/NLS/INF files\n")
                .append("[NLS] locale.nls, l_intl.nls and codepage tables hashed, staged at two Wine search paths\n")
                .append(mallocTracking
                    ? "[ALLOCATOR A/B] BOX64_MALLOC_HACK=2; track special mmap/free only in this run; tagging retained\n"
                    : isolateHeap
                        ? "[HEAP TAG A/B] Explicit child-process trial only; Box64 must confirm mallopt; NOT a memory fix\n"
                        : "[HEAP TAG] Android pointer-tag protection retained; no mitigation applied\n")
                .append("[PE VERIFIED] first-party Windows x86-64 PE (not Linux ELF), SHA256 OK\n")
                .append("[WINESERVER] ARM64 launcher -> Box64 -> Wine wineserver64\n")
                .append("[PREFIX] private application directory; no root/network\n");
            ProcessBuilder pb = bootstrapOnly
                ? new ProcessBuilder(box.getAbsolutePath(), wine.getAbsolutePath(), "wineboot.exe", "--init")
                : new ProcessBuilder(box.getAbsolutePath(), wine.getAbsolutePath(), guest.getAbsolutePath());
            report.append(bootstrapOnly
                ? "[BOOT COMMAND] Wine64 -> wineboot.exe --init (first-party packaged Wine only)\n"
                : "[EXE COMMAND] Wine64 -> own verified rm11_probe.exe\n");
            pb.directory(work);pb.redirectErrorStream(true);
            Map<String,String> env=pb.environment();
            env.put("BOX64_DYNAREC", mode == ProbeMode.NORMAL ? "1" : "0");
            env.put("BOX64_LOG","1");
            report.append("[V235 TRIAL] Box64 Dynarec=").append(env.get("BOX64_DYNAREC"))
                .append("; normal Android heap-tag protections unchanged.\n");
            // Keep the opt-out entirely scoped to one user-requested subprocess.
            if (isolateHeap) env.put("RM11_TEST_DISABLE_BIONIC_HEAP_TAGS","1");
            else env.remove("RM11_TEST_DISABLE_BIONIC_HEAP_TAGS");
            if (mallocTracking) {
                env.put("BOX64_MALLOC_HACK", "2");
                env.put("BOX64_ROLLING_LOG", "16");
                env.put("BOX64_SHOWBT", "1");
            } else {
                env.remove("BOX64_MALLOC_HACK");
                env.remove("BOX64_ROLLING_LOG");
                env.remove("BOX64_SHOWBT");
            }
            env.put("BOX64_LD_LIBRARY_PATH",new File(root,"usr/lib/x86_64-linux-gnu/wine/x86_64-unix").getAbsolutePath()
                +":"+new File(root,"usr/lib/x86_64-linux-gnu").getAbsolutePath());
            env.put("WINEDLLPATH",new File(root,"usr/lib/x86_64-linux-gnu/wine").getAbsolutePath());
            env.put("WINESERVER",bridge.getAbsolutePath());
            env.put("RM11_WINESERVER64_PATH",server.getAbsolutePath());
            env.put("WINELOADER",wine.getAbsolutePath());
            env.put("WINEPREFIX",prefix.getAbsolutePath());env.put("WINEARCH","win64");
            env.put("HOME",ctx.getFilesDir().getAbsolutePath());
            env.put("XDG_CACHE_HOME",ctx.getCacheDir().getAbsolutePath());
            // Keep actionable Wine initialization evidence; unlike warn-only mode,
            // process/server channels show whether client-server handshake advances.
            // Avoid per-request server tracing in the first Wine boot: on interpreted
            // Wine this can be excessively slow. Fatal errors + process progress stay visible.
            env.put("WINEDEBUG","-all,err+all,warn+all,+process");
            File xdgRuntime=new File(ctx.getFilesDir(),"rm11-v235-runtime");
            if (!xdgRuntime.isDirectory() && !xdgRuntime.mkdirs())
                throw new IllegalStateException("Cannot prepare private XDG runtime");
            xdgRuntime.setReadable(false,false);xdgRuntime.setWritable(false,false);
            xdgRuntime.setReadable(true,true);xdgRuntime.setWritable(true,true);
            xdgRuntime.setExecutable(true,true);
            env.put("XDG_RUNTIME_DIR",xdgRuntime.getAbsolutePath());
            env.put("TMPDIR",ctx.getCacheDir().getAbsolutePath());
            env.put("WINEDATADIR",new File(root,"usr/share/wine").getAbsolutePath());
            // Android's inherited LC_*/TZ can confuse Wine/glibc locale bootstrap.
            env.keySet().removeIf(k -> k.startsWith("LC_"));
            env.put("LANG","C");env.put("LC_ALL","C");env.put("LANGUAGE","C");env.put("TZ","UTC");
            env.remove("LD_PRELOAD"); env.remove("DISPLAY");env.remove("WAYLAND_DISPLAY");
            process=pb.start();
            Process child=process;
            HeadTailLog bounded=new HeadTailLog();
            BootTrace trace = new BootTrace();
            Thread drain=new Thread(() -> {
                try(InputStream src=child.getInputStream()) {
                    byte[] buf=new byte[2048];int n;
                    while((n=src.read(buf))!=-1) {bounded.append(buf,n);trace.observe(buf,n);}
                } catch(Exception ignored) { }
            },"rm11-v22-wine-output");
            drain.setDaemon(true);drain.start();
            long started = System.nanoTime();
            int deadline = bootstrapOnly ? BOOT_TIMEOUT_SECONDS : TIMEOUT_SECONDS;
            report.append("[TIME BUDGET] ").append(deadline).append(" seconds; controlled stop on timeout\n");
            boolean finished=process.waitFor(deadline,TimeUnit.SECONDS);
            if(!finished) {process.destroyForcibly();process.waitFor(2,TimeUnit.SECONDS);}
            drain.join(1200);
            String output = bounded.text();
            boolean written=success.isFile() && success.length()==MARKER.getBytes(StandardCharsets.UTF_8).length
                && MARKER.equals(new String(Files.readAllBytes(success.toPath()),StandardCharsets.UTF_8));
            int code=finished?process.exitValue():-1;
            report.append("[ELAPSED MS] ")
                .append(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)).append('\n');
            report.append(trace.summary());
            report.append("[SERVER SPAWN] helper entered: ")
                .append(output.contains("RM11_WINESERVER_BRIDGE_ENTERED")?"YES":"NOT OBSERVED").append('\n');
            report.append("[SERVER CTYPE] unresolved GNU ctype: ")
                .append(output.contains("__ctype_b_loc not found") || output.contains("__ctype_tolower_loc not found")
                    ? "YES":"NOT OBSERVED").append('\n');
            boolean sysReg = new File(prefix, BOOT_REG).isFile();
            boolean userReg = new File(prefix, USER_REG).isFile();
            report.append("[PREFIX STATUS] system.reg=").append(sysReg ? "YES":"NO")
                .append(" user.reg=").append(userReg ? "YES":"NO")
                .append('\n');
            if (bootstrapOnly) {
                if (finished && code == 0 && sysReg && userReg) {
                    try (FileOutputStream bootStamp = new FileOutputStream(receipt)) {
                        bootStamp.write("RM11_V235_BOOT_OK\n".getBytes(StandardCharsets.UTF_8));
                        bootStamp.getFD().sync();
                    }
                    report.append("[BOOT READY] wineboot exited 0 and created both registry files. ")
                        .append("This does NOT prove Windows EXE execution or game compatibility.\n");
                } else {
                    report.append(finished ? "[BOOT NOT READY] Wine bootstrap ended without full evidence.\n"
                        : "[BOOT TIMEOUT] wineboot did not finish by 120 seconds. No Windows EXE attempted.\n");
                    if (trace.initFirstThread)
                        report.append("[IPC OBSERVED] First-thread request seen; its successful response is NOT proven.\n");
                    report.append("[NEXT CHECK] If this times out, inspect first Wine err: lines, IPC observations and prefix files.\n");
                }
            } else if (!finished) {
                report.append("[EXE TIMEOUT] Wine Windows EXE did not finish within 55 seconds.\n");
            }
            if (bootstrapOnly) report.append("[PREFIX CHECK] drive_c=")
                .append(new File(prefix,"drive_c").isDirectory() ? "YES" : "NO")
                .append(" dosdevices=")
                .append(new File(prefix,"dosdevices").isDirectory() ? "YES" : "NO")
                .append('\n');
            if (!finished && bootstrapOnly) {
                // The main Wine process may have spawned a persistent wineserver.
                // Ask the server to stop for ONLY this version's private WINEPREFIX.
                // This is a bounded best-effort operation, not evidence of successful boot.
                Process cleanup = null;
                try {
                    ProcessBuilder stop = new ProcessBuilder(box.getAbsolutePath(),server.getAbsolutePath(),"-k");
                    stop.environment().putAll(env);
                    stop.redirectErrorStream(true);
                    stop.redirectOutput(ProcessBuilder.Redirect.to(new File("/dev/null")));
                    cleanup=stop.start();
                    boolean stopped=cleanup.waitFor(6,TimeUnit.SECONDS);
                    report.append("[PRIVATE SERVER CLEANUP] wineserver -k: ")
                        .append(stopped ? "exit="+cleanup.exitValue() : "timed out").append('\n');
                    if (!stopped) cleanup.destroyForcibly();
                } catch(Exception stopError) {
                    report.append("[PRIVATE SERVER CLEANUP] unconfirmed: ")
                        .append(stopError.getClass().getSimpleName()).append('\n');
                } finally { if (cleanup != null && cleanup.isAlive()) cleanup.destroyForcibly(); }
            }
            if (output.contains("RM11_ENV_SNAPSHOT_CREATED"))
                report.append("[OWNERSHIP] secure_getenv snapshot bridge was exercised\n");
            if (output.contains("RM11_ENV_BORROWED_FREE_PREVENTED"))
                report.append("[OWNERSHIP] invalid free on a borrowed snapshot was prevented\n");
            if (isolateHeap && !output.contains("RM11_HEAP_ISOLATION_APPLIED"))
                report.append("[NOT APPLIED] Missing subprocess confirmation; cannot infer result.\n");
            report.append("Exit code: ").append(code).append(finished?"":" (TIMEOUT)")
                .append(bootstrapOnly ? "\nWin32 marker: NOT TESTED (boot phase only)"
                    : "\nWin32 marker verified: " + (written ? "YES" : "NO"))
                .append("\nWine/Box64 output (bounded):\n").append(output).append("\n");
            if (!bootstrapOnly) report.append(classify(code,!finished,written,output));
        } catch(Exception e) {
            report.append("[RUNTIME ERROR] ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append('\n');
        } finally {
            if(process!=null && process.isAlive()) process.destroyForcibly();
        }
        return report.toString();
    }
}
