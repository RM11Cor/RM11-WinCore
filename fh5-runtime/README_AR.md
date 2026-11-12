# FH5 Runtime R1 - real startup readiness gate

Target: REDMAGIC 11 Pro / Android 16 / ARM64, using a licensed Forza Horizon 5 PC installation.

This is a **new runtime branch of work**, separate from the research M1-M80 tools.

## R1

- Inspect the actual `ForzaHorizon5.exe` PE64 header and static imported DLLs from the 100+ GB local ZIP.
- Extract **only the executable into a temporary Termux file**, delete it immediately and upload only aggregated diagnostic counts.
- Detect whether the binary has import hints for Steam, Xbox runtime or another launcher, without attempting to bypass licensing.
- Produce `/sdcard/Download/FH5_BOOT_R1_REPORTS.zip`; it contains no executable, game content or private paths.
- Download `FH5_BOOT_TEST.bat` into Downloads for later use after the game is safely extracted and launched within a working Wine+FEX environment. Don't run it against the ZIP.

## Reality check

The current `app/` on this branch is a bounded PE64 experiment, **not** a working Wine + FEX + VKD3D Android runtime. Shipping an APK that actually launches this game still requires integration of those components, process/window/graphics/audio services and account/launcher compatibility.

No fake success stages. Next milestones: R2 - runtime environment capability inventory and loader gate; R3 - boot trace and first failing API/graphics call; R4 - real game window/first frame; then input/performance.

Official game requires DirectX 12 and a legitimate account/launcher. No DRM/anti-cheat bypass, no distribution of game binaries or game data.

## Privacy

Never upload `~/.fh5_m*/PRIVATE*.json` or `FH5_BOOT_RAW.log` without redaction; both can contain local private paths.
