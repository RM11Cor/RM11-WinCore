# RM11-WinCore · complete Bannerlator engine integration

This branch was created from the **original RM11-WinCore archive**
`c21a0721370ec028875a60b77d07fdf4bb57cdbc`.
Nothing is rewritten or deleted in that preserved source archive.

## Integration source / actual build

- **Engine source:** The412Banner/Bannerlator commit `146158413f25e28f9ad04d921d0b7b806f86cc53` (3.1.7 baseline).
- **Verified additional diagnostics:** RM11Cor/RM11-WinCore commit `35c3a2d2437dd1d52c7608609ac82458f0d56a62`, used as an immutable patch source.
- **Packaging:** `.github/workflows/rm11-integrated-bannerlator-apk.yml`. Runs the complete upstream Android build including asset construction and native libraries, rather than gluing selected DLLs to the old incomplete loader.
- **Identity for staged testing:** `com.rm11.wincore.integrated`. Intentionally does not overwrite an installed RM11 legacy app or KERNIX.
- **Built-in functions:** container and game shortcut settings; Wine/Proton and translation component managers as upstream supports; DXVK/VKD3D/Turnip and frame/performance controls; input and XServer drawer from full upstream, with provenance checks. Some components are optional/downloading on demand as in upstream, rather than claiming every released component already lives in APK.

## Verified state and next integration gate (2026-11-02)

- The **latest successful** full-engine run at this checkpoint is
  [41469912051](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41469912051)
  (commit `66132fc`). Its Android build, APK signature verification,
  package identity checks, runtime asset checks, and artifact upload passed.
  It is **not** evidence that the original KERNIX launcher/UI was migrated.
- The newer [41469945776](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41469945776)
  failed before compilation because Android SDK manager downloaded a corrupted
  NDK archive (`Archive is not a ZIP archive`); its failed job has been
  retried. Do not report the KERNIX branding changes as APK-verified until
  a build containing them succeeds.
- The source inventory, storage/API conflicts, and staged UI migration
  gates are documented in
  [KERNIX-UI-MIGRATION-INVENTORY.md](KERNIX-UI-MIGRATION-INVENTORY.md).
  **Next code milestone:** implement a real KERNIX game-library shell on top
  of the upstream game/shortcut APIs, not merely a launcher label change.
- **Device testing remains outstanding** for all integrated candidates.

## Definition of done (not currently met)

1. Build a signed APK with all core engine assets, verified package identity, and baseline tests passing.
2. Compare and migrate **original RM11 UI and features** after an interface inventory and conflict check. Current candidate initially uses the working Bannerlator UI as a foundation, not the old RM11-specific files UI. Do not claim otherwise.
3. Preserve settings selection and saved per-game profiles; show suggested compatibility profiles as suggestions only, never assert a game works from static imports.
4. On-device verification: live game launch, true input mapping, first frame, per-game persistence, on-screen overlay/frame generation features (conditional support), and no regression in a working control game.
5. Only after the above, decide how to replace the old application package safely (backup or migration); do not make a different application ID look like a drop-in upgrade.
6. Preserve upstream GPL-3.0 notices, source provenance, and required license obligations when distributing modified APKs.

**Important:** No single implementation is compatible with literally every Windows game on Android. Anti-cheat, hardware capabilities, unsupported APIs and other restrictions remain.

## Do not confuse proof types

GitHub compilation proves APK packaging, not that all its components work on a given phone. A single game running proves that game's configuration only. An FPS number requires actual frame presentation evidence, not Android Activity lifecycle or the graphics UI frame clock.
