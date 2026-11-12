# CarX Street PC port — user-provided inspector v0.2 evidence and v0.4 diagnostic gate

Date: 2026-11-12. Scope: **read-only original Windows game data**; no game binary or bundle contents distributed.

## Exact on-phone source inspection evidence

- Inspector `0.2.0` completed scanning folder "CarX Street" on REDMAGIC NX809J Android 16, ARM64-v8a.
- **906 files**, **21 directories**, **22,710,138,866 bytes** known, no unknown size, scan incomplete **false**.
- `CarX Street Launcher.exe` and `GameAssembly.dll` both recognized as Windows PE x86-64, *not* Android ARM64 programs.
- `global-metadata.dat` exists. **64 initial bytes did not contain the classic IL2CPP magic at offset zero**; metadata version unavailable. This alone does NOT distinguish encryption/obfuscation, wrong file/version, or a custom/nonstandard file layout. Never claim an encryption method is known.
- **808** `StreamingAssets/aa/StandaloneWindows64/*.bundle` files found, totaling **19,819,549,827 bytes**. 12 sample headers all parsed as `UnityFS` bundle container header format **8**, with string fields `5.x.x` and `0.0.0`. These are **placeholder strings** and must NEVER be declared the actual Unity Editor or game engine version.
- `catalog.json` 16KiB sample contains `m_InternalIds` and Windows64 text. Full 11.79 MB catalog dependencies were NOT parsed, so no proof of cross-platform asset compatibility.
- `boot.config` key names were read, values deliberately excluded.
- All `native_game_runtime_available`, `game_logic_on_android_arm64_proven`, `actual_android_unity_asset_load_proven`, `renderer_first_frame_proven` are **false**.
- The user's prior v0.1 scan showed 906 files and the same PC EXE / GameAssembly SHA prefix; no verified native port status from either report.

## v0.4 follow-up implemented

- Strict bounded candidate version read from Unity `globalgamemanagers` and `resources.assets` serialized file headers (first 256 bytes each, no full asset load), with Java adversarial header tests and fail-closed unknown handling.
- Limited 4KiB metadata prefix scan for IL2CPP standard `AF 1B B1 FA` signature and 16-byte initial hex; no decryption, circumvention, dumping or source reconstruction.
- Existing UnityFS, Android device details and Windows64 bundle census remain.
- VersionCode **4**, applicationId `com.rm11cor.carxstreet.portlab`, signing identity pinned and reused from permanent v0.3.0. v0.3 -> v0.4 Android in-place update expected by package/signature rules, pending actual device install confirmation.
- Distinguish proven build/package/signature from unproven actual game boot and first frame. Do not falsely claim the PC Unity game is converted to Android through JSON/header inspection.

## Next engineering decision gate

If `globalgamemanagers` yields a valid Unity Editor version, compare it to lawful Unity/IL2CPP runtime access, matching Android-target game logic and platform assets; original Windows x86-64 IL2CPP cannot be loaded as native Android ARM64 code. If the metadata prefix remains nonstandard, investigate *metadata format/protection classification*, not blind decoding or fabricated IL2CPP metadata version. Without legally compatible ARM64 game logic or an engine implementation, no native playable port exists.

Reference for UnityFS placeholders and actual SerializedFile version location: UnityPy `SerializedFile.py` parser and Unity AssetBundle documentation.
