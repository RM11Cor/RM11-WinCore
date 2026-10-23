package com.rm11.autocore.runtime;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Only measured ARM64 kernel-exposed registers may enter the app's Wine prefix.
 * Preserve existing keys and a pristine registry backup; no fabricated CPU flags.
 */
public final class WineCpuRegistryBootstrap {
    private static final String[] NAMES = {
        "CP 4030","CP 4020","CP 4021","CP 4031","CP 4038","CP 403A",
        "CP 4024","CP 4039","CP 4032","CP 5801","CP 4000"
    };
    private static final String CPU_HEADER = "[Hardware\\\\Description\\\\System\\\\CentralProcessor\\\\0]";
    private WineCpuRegistryBootstrap() {}

    public static String prepare(RuntimeLayout p) {
        try {
            Path exe = p.apkNativeLibs.resolve("librm11cpuprobe.so");
            if (!Files.isRegularFile(exe, LinkOption.NOFOLLOW_LINKS))
                return "CPU_PROBE_NOT_PACKAGED";
            ProcessBuilder builder = new ProcessBuilder(exe.toString());
            builder.redirectErrorStream(true);
            Process child = builder.start();
            if (!child.waitFor(5, TimeUnit.SECONDS)) {
                child.destroyForcibly();
                return "CPU_PROBE_TIMED_OUT_NO_REGISTRY_CHANGE";
            }
            if (child.exitValue() != 0)
                return "CPU_PROBE_REJECTED_OR_CRASHED_exit=" + child.exitValue();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = child.getInputStream()) {
                byte[] buf = new byte[1024];
                int n;
                while ((n = in.read(buf)) != -1) {
                    if (out.size() + n > 4096) return "CPU_PROBE_OUTPUT_OVER_LIMIT";
                    out.write(buf, 0, n);
                }
            }
            final Map<String, Long> cpu;
            try {
                cpu = parseMeasuredValues(
                        new String(out.toByteArray(), StandardCharsets.US_ASCII));
            } catch (IllegalArgumentException invalidProbe) {
                // Distinguish missing measurements from a Wine registry parser
                // problem without exposing register values or app-private paths.
                return "CPU_PROBE_MEASUREMENTS_REJECTED_" + invalidProbe.getClass().getSimpleName();
            }
            String registryOutcome = installMeasuredRegistryValues(p, cpu);
            return registryOutcome;
        } catch (Exception e) {
            return "CPU_REGISTRY_UNCHANGED_" + e.getClass().getSimpleName();
        }
    }

    public static Map<String, Long> parseMeasuredValues(String data) {
        if (data == null || !data.startsWith("RM11_CPU_ID_STATUS=MEASURED_EL0_HWCAP_CPUID\n"))
            throw new IllegalArgumentException("Unverified CPU register probe");
        LinkedHashMap<String, Long> values = new LinkedHashMap<>();
        for (String line : data.split("\n")) {
            if (line.startsWith("RM11_CPU_ID_STATUS=")) continue;
            int idx = line.indexOf('=');
            if (idx < 0) throw new IllegalArgumentException("Malformed register row");
            String key = line.substring(0, idx);
            boolean expected = false;
            for (String n : NAMES) if (n.equals(key)) expected = true;
            if (!expected || values.containsKey(key) ||
                    !line.substring(idx + 1).matches("[0-9a-f]{16}"))
                throw new IllegalArgumentException("Invalid CPU measurement");
            values.put(key, Long.parseUnsignedLong(line.substring(idx + 1), 16));
        }
        if (values.size() != NAMES.length || values.get("CP 4000") == 0L ||
                values.get("CP 5801") == 0L)
            throw new IllegalArgumentException("Incomplete host CPU measurements");
        return values;
    }

    public static String renderFirstCpuKey(Map<String, Long> values, long timestamp) {
        if (values == null || values.size() != NAMES.length ||
                values.get("CP 4000") == null || values.get("CP 4000") == 0L ||
                values.get("CP 5801") == null || values.get("CP 5801") == 0L)
            throw new IllegalArgumentException("Incomplete feature record");
        StringBuilder b = new StringBuilder(CPU_HEADER).append(' ').append(timestamp).append('\n');
        for (String name : NAMES) {
            Long val = values.get(name);
            if (val == null) throw new IllegalArgumentException("Missing measurement " + name);
            b.append('"').append(name).append("\"=hex(b):");
            for (int shift = 0; shift < 64; shift += 8) {
                if (shift > 0) b.append(',');
                b.append(String.format(java.util.Locale.ROOT, "%02x", (val >>> shift) & 255L));
            }
            b.append('\n');
        }
        return b.append('\n').toString();
    }

    public static String insertOnlyIfMissing(String old, String cpuSection) {
        if (!old.startsWith("WINE REGISTRY Version 2\n") ||
                !old.contains(";; All keys relative to REGISTRY\\\\Machine"))
            throw new IllegalArgumentException("Unknown Wine registry format");
        if (old.contains(CPU_HEADER) ||
                old.contains("[Hardware\\\\Description\\\\System\\\\CentralProcessor\\\\"))
            throw new IllegalStateException("Existing registry CPU records preserved");
        int at = old.indexOf("\n[Software\\\\");
        if (at < 0) throw new IllegalArgumentException("Unknown Wine section order");
        return old.substring(0, at + 1) + cpuSection + old.substring(at + 1);
    }

    public static String installMeasuredRegistryValues(RuntimeLayout p, Map<String, Long> cpu) {
        try {
            Path trusted = p.appFiles.toRealPath();
            Path prefix = p.winePrefix.toRealPath();
            if (!prefix.startsWith(trusted) || !Files.isRegularFile(p.winePrefixMarker()))
                return "CPU_REGISTRY_UNTRUSTED_PREFIX_BLOCKED";
            Path registry = prefix.resolve("system.reg");
            if (Files.isSymbolicLink(registry) ||
                    !Files.isRegularFile(registry, LinkOption.NOFOLLOW_LINKS))
                return "CPU_REGISTRY_INVALID_FILE";
            if (Files.size(registry) < 100000 || Files.size(registry) > 15000000)
                return "CPU_REGISTRY_UNEXPECTED_SIZE";
            String old = new String(Files.readAllBytes(registry), StandardCharsets.UTF_8);
            if (old.contains(CPU_HEADER)) return "CPU_REGISTRY_ALREADY_PRESENT_UNCHANGED";
            String next;
            try {
                next = insertOnlyIfMissing(old,
                        renderFirstCpuKey(cpu, System.currentTimeMillis() / 1000));
            } catch (IllegalStateException e) {
                return "CPU_REGISTRY_OTHER_KEYS_PRESENT_UNCHANGED";
            } catch (IllegalArgumentException e) {
                return "CPU_REGISTRY_FORMAT_REJECTED_UNCHANGED";
            }
            Path backup = prefix.resolve("system.reg.before-rm11-v265");
            Path pending = prefix.resolve("system.reg.rm11-v265-pending");
            if (Files.exists(backup, LinkOption.NOFOLLOW_LINKS) ||
                    Files.exists(pending, LinkOption.NOFOLLOW_LINKS))
                return "CPU_REGISTRY_BACKUP_OR_PENDING_EXISTS_UNCHANGED";
            Files.copy(registry, backup);
            try (FileOutputStream stream = new FileOutputStream(pending.toFile())) {
                stream.write(next.getBytes(StandardCharsets.UTF_8));
                stream.getFD().sync();
            }
            try {
                Files.move(pending, registry, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception e) {
                return "CPU_REGISTRY_ATOMIC_MOVE_UNAVAILABLE_OR_FAILED";
            }
            return "CPU_REGISTRY_MEASURED_VALUES_INSTALLED_UNVERIFIED_BY_WINE";
        } catch (Exception e) {
            return "CPU_REGISTRY_UNCHANGED_" + e.getClass().getSimpleName();
        }
    }
}
