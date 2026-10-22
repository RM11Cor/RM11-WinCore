package com.rm11.autocore.integration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * First RM11 integration boundary: alternatives, NOT stacked emulators.
 * This is a catalogue of runtime contracts, not a claim the binaries are bundled.
 */
public final class RuntimeCatalog {
    private RuntimeCatalog() {}

    public enum Backend { BIONIC_ARM64EC_FEX, GLIBC_BOX64 }

    public static final class Profile {
        public final Backend backend;
        public final String libc;
        public final String windowsRuntime;
        public final String cpuTranslator;
        public final boolean requiresLinuxRootFs;
        public final List<String> upstreamProjects;

        private Profile(Backend backend, String libc, String windowsRuntime,
                        String cpuTranslator, boolean requiresLinuxRootFs, String... upstream) {
            this.backend = backend;
            this.libc = libc;
            this.windowsRuntime = windowsRuntime;
            this.cpuTranslator = cpuTranslator;
            this.requiresLinuxRootFs = requiresLinuxRootFs;
            this.upstreamProjects = Collections.unmodifiableList(Arrays.asList(upstream));
        }
    }

    public static Profile profile(Backend backend) {
        if (backend == null) throw new IllegalArgumentException("Backend is required");
        switch (backend) {
            case BIONIC_ARM64EC_FEX:
                return new Profile(backend, "Android Bionic", "Wine ARM64EC / WoW64",
                        "FEX ARM64EC + WoW64 DLLs", false, "GameNative", "FEX-Emu", "Hangover");
            case GLIBC_BOX64:
                return new Profile(backend, "Linux glibc in a guest rootfs", "Wine x86_64 / WoW64",
                        "Box64", true, "Winlator", "Box64", "DroidDeck (guest syscall lessons)");
            default:
                throw new IllegalArgumentException("Unknown backend");
        }
    }

    /** Do NOT combine a glibc loader with a Bionic runtime process. */
    public static void requireCompatible(Backend selected, String libc, String translator) {
        Profile p = profile(selected);
        if (!p.libc.equals(libc) || !p.cpuTranslator.equals(translator)) {
            throw new IllegalArgumentException("Runtime components belong to incompatible backends: " + selected);
        }
    }
}
