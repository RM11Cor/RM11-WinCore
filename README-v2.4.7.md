# RM11-WinCore v2.4.7 — Compatibility Preflight

This is a read-only **diagnostic/preflight** APK. It does not run Windows games, and cannot automatically install any runtime yet.

## New capability

- Reads game title/PE/engine/store metadata from v2.4.6 unchanged.
- Constructs a per-folder **compatibilityPreflight** object in local JSON schema v3.
- Suggests component **roles**, not specific executable releases: x86 translator, Wine/Proton, DXVK (D3D8-11), VKD3D (D3D12), Vulkan driver.
- Flags obvious Easy Anti-Cheat/BattlEye filenames without claiming compatibility or bypassing protections.
- Records provenance/uncertainty. No game-title hardcoding and no fabricated CPU/RAM or graphic requirements.
- No game copies, patching or DRM bypass. Stored report uses Android app-private storage.

## Trust model

Only locally observed files are evidence here. A PE import is a **hint**; engines can load APIs dynamically. Without external vendor evidence no "best" FEX/Proton/Turnip release is certified. Anticheat support can require game publisher enablement. Any future online component downloads must have allowlisted sources, checksums/signatures, and explicit activation/rollback.

## Update

Same applicationId `com.rm11.autocore` as v2.4.4+; versionCode 8 (was 7). Use the existing GitHub encrypted secrets with the *same* signing key to build a release APK; do **not** upload the keystore.

## Building

Upload ZIP with exact name `RM11-WinCore-v2.4.7-source.zip` to repository root. Existing GitHub Action selects latest archive and builds signed APK. Before installing confirm successful signing verification.
