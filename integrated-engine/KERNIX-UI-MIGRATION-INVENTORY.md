# KERNIX UI migration inventory — 2026-11-02

This is an evidence-backed **inventory and migration contract**, not a claim that the
KERNIX UI is already installed in the integrated APK.

## Source boundaries

- Original KERNIX application: `archive-kernix-legacy-rc325-20261102`,
  `app/src/main/AndroidManifest.xml`. Launcher is
  `com.rm11.autocore.RM11GameLibraryActivity`; the old diagnostic
  `MainActivity` is deliberately **not** the launcher.
- Integrated engine: The412Banner/Bannerlator
  `146158413f25e28f9ad04d921d0b7b806f86cc53`,
  currently built by `.github/workflows/rm11-integrated-bannerlator-apk.yml`.
  Its launcher is `com.winlator.star.MainActivity`, navigation is Compose
  `AppNavGraph.kt` / `AppDrawer.kt`, game wall is `GamesWallScreen.kt`.
- Integrated test package: `com.rm11.wincore.integrated`; do **not**
  overwrite or relabel it as an in-place upgrade of the legacy package.
- Current staged app still uses the **Bannerlator UI and game-management
  model**. The KERNIX branding patch changes visible labels, **not**
  the launcher architecture or user-data storage model.

## UI/feature inventory and conflict map

| Legacy KERNIX source | Integrated engine counterpart | Safe migration rule |
| --- | --- | --- |
| `RM11GameLibraryActivity.java` launcher / game tiles | `MainActivity.kt` + `GamesWallScreen.kt` | Do **not** replace MainActivity with legacy Activity. First build a KERNIX Compose game-library shell using upstream launch APIs. |
| `RM11GameLibraryStore.java` | `ContainerManager` shortcuts and game details | Different storage models. Map titles/covers/paths with explicit import preview; never silently rewrite shortcuts or game directories. |
| `R4PrimaryExePickerV49076.java` | Upstream file picker / shortcut creation | Preserve user-requested single file entrypoint, but use the engine's supported document/drive paths. No assumption that raw Android path is visible in Wine. |
| `RM11AppearanceActivity.java`, `R4CinematicGLViewV49061.java`, `R4WorldSceneV49060.java`, `assets/r4/*` | Compose theme, `AppearanceScreen.kt` | UI artwork is not a working engine integration. Port visual elements only after navigation and lifecycle compatibility are checked. |
| `RM11VirtualGamepadOverlayV49037.java`, `RM11ControllerBindingsV49041.java` | `InputControlsManager`, `InputControlsView` and engine input pipeline | Do not run two simultaneous virtual controllers. Use one engine-owned input mapping and validate ABXY, both sticks, triggers and XInput on-device. |
| `R4ManualComponentsV49069.java`, `R4ComponentCatalogV49068.java` | Wine/FEX/Box64/graphics-wrapper and driver managers | Treat discovered upstream versions as metadata only. Only ABI-verified installed builds can appear as selectable runnable components. |
| Legacy KERNIX runtime/probes and `NovaWineExeLauncher` | Complete upstream Wine/FEX/XServer runtime | Do **not** transplant legacy launch or graphics bootstrap over working upstream. Port diagnostics as isolated read-only observers. |

## Data and API boundaries

1. Legacy library entries are stored in private `SharedPreferences` under
   `rm11_v49038_game_library` / `items`; the separate integrated package
   cannot assume it can read them. Do not copy private preferences by guesswork.
2. The legacy store records EXE paths and titles. An EXE path alone does not
   guarantee that the Bannerlator container can resolve the path, own the
   required prefix, or launch the game.
3. Do not delete or overwrite user games, existing prefixes, covers, saves,
   mappings or profiles as part of the UI migration.
4. Any future migration must be opt-in with a preview, deduplication, rollback
   or cancel path, and explicit persistence tests. The original app stays installed.
5. Preserve original upstream licensing/provenance and attribution.

## Execution gates (ordered)

- **Gate A — CI baseline:** signed isolated APK; runtime assets, ARM64
  libraries, application ID and APK signature verified by CI.
- **Gate B — KERNIX shell:** add an actual KERNIX game-library screen
  to the integrated app and make its navigation explicit, without replacing
  upstream engine services. Add a CI check for the actual launcher destination,
  not just an app-name string.
- **Gate C — game API adapter:** game import/remove/launch actions go through
  upstream `ContainerManager` and shortcut/prefix APIs; validate on a
  disposable test profile and keep existing data untouched.
- **Gate D — per-game settings:** bind the engine's existing selectable
  Wine/Proton/FEX/DXVK/VKD3D/Turnip settings; only verified installed versions
  are actionable. Test persistence independently of runtime success.
- **Gate E — input and first-frame device evidence:** verify actual controller
  events, swapchain and presentation, overlay, and frame-generation availability
  where supported. CI compilation is not evidence of a running game.
- **Gate F — migration/release:** user-approved data import, license audit,
  regression checks, and only then consider replacing the old app.

## CI evidence at inventory time

- Workflow run `41469912051` (commit `66132fc`) completed successfully,
  including APK package, signature and core asset checks. Its UI is **not**
  the migrated KERNIX launcher.
- Newer run `41469945776` (commit `42e8736`) failed during the
  NDK 26.1.10909125 download: Android sdkmanager reported
  `Archive is not a ZIP archive`. The failure happened **before**
  KERNIX branding and Gradle compilation; no inference about those steps is
  possible from that failed attempt. Failed job was retried.
