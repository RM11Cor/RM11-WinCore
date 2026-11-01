# KERNIX — Clean Engine Phase (2026-11-02)

This branch is the **only clean integration workspace** for the Bannerlator 3.1.7 engine rebase.

## Cleanup completed
- Legacy RC / v2 / v4 application sources, experiments, test launchers, old rootfs references, and old GitHub Actions workflows are **absent from this branch's working tree**.
- Historical commits and branches are NOT deleted. An explicit backup pointer remains at `archive-kernix-legacy-rc325-20261102`.
- The pinned GPL-3.0 Bannerlator source submodule, engine lock, verification tool, and **two** upstream-only CI workflows are retained.
- No legacy Gradle build workflow is enabled from this branch.

## Strict isolation
1. Build ONLY from `kernix-next-clean-engine`, with recursive submodules.
2. Never merge old RC branches or copy old build outputs, Wine prefixes, rootfs, .so files, cached DLLs, or Gradle-generated intermediates into this branch.
3. Keep engine source pinned to `146158413f25e28f9ad04d921d0b7b806f86cc53`, and verify ABI and hashes before changing dependencies.
4. The current APK build is **unmodified upstream Bannerlator**, not a branded KERNIX successor. Do not install over Bannerlator or legacy KERNIX.
5. Do not turn on phone testing of quarantined legacy X11/Proton paths until the Android-wide-freeze safety gate passes.
6. Add KERNIX packaging/identity, tested source integration, per-game profiles and controller layer **after** upstream build and audit pass. Preserve source licenses.

## Status indicators
SOURCE_PRESENT != APK_COMPILED != KERNIX_INTEGRATED != DEVICE_QUALIFIED.
