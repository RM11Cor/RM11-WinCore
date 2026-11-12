# CarX Street v0.7 — verified real phone PC source imports & native Android port decision

Source: user-provided CarX_Street_PC_Port_Report_v0.7.json, generated on the user's Android device from their own locally accessible CarX Street PC installation using the app's Storage Access Framework (SAF). Privacy: do not commit raw user report, full file paths, original proprietary DLLs, metadata or personal phone identifiers into the repository.

Date: 2026-11-12. Scope: CarX branch only; KERNIX remains paused and FH5 branch remains independent.

## Newly *actual source verified* (distinguish from synthetic test data)

- Source scan: 906 files, 21 directories, 22,710,138,866 bytes. Incomplete scan = false.
- Both original binaries are **Windows PE32+ x86-64**, and SAF random-access reads and PE import descriptor parsing succeeded:
  - GameAssembly.dll: 142,049,792 bytes, 7 PE sections, **15** static import DLL names. Includes baselib.dll, kernel32.dll, user32.dll, ws2_32.dll, advapi32.dll, ole32.dll, oleaut32.dll, bcrypt.dll, WinRT API-set DLLs, and OS DLLs.
  - UnityPlayer.dll: 35,734,960 bytes, 8 PE sections, **26** static import DLL names. Crucial original Windows renderer imports **d3d11.dll, dxgi.dll and opengl32.dll**; also gdi32.dll, hid.dll, imm32.dll, winhttp.dll, winmm.dll, kernel32.dll and several OS DLLs.
  - Static Steam/EOS/EAC names absent in *these two PE import tables* only. The source inventory includes EasyAntiCheat components; launcher and dynamic dependency loading were not audited. Absence in two static tables must not be represented as lack of runtime dependencies, permission, anti-cheat or online requirements.
- Unity editor version candidate **6000.3.8f1** independently agrees in the original globalgamemanagers and resources.assets headers. This is a Windows game source version, NOT a usable native Android UnityPlayer runtime.
- Unity Addressables catalog parsed in full via SAF, without file copying: **54,490 internal IDs; 807 .bundle-like references; 807 containing StandaloneWindows64; 0 StandaloneOSX; 0 StandaloneLinux64; 1 string containing Android; 2 containing shader**.
- Source directory scanner independently counted **808 actual StandaloneWindows64 .bundle files totaling 19,819,549,827 bytes**. A count difference 808 vs 807 is **not proof of a missing or corrupt asset**. One may be unlisted/dynamic or references may be duplicated; no source-accurate per-file set reconciliation has occurred. Do not invent the unmatched filename.
- The one Android-named entry is **not proof of any Android-target AssetBundle**. It is only an internal string with the substring Android. The actual entry, its file type and whether it is a compatible Unity bundle remain unknown. Android compatible graphics/asset data is not established.
- Original global-metadata.dat first 4096 bytes did not contain classic IL2CPP magic. This doesn't prove encryption or the absence of native source.
- Original REDMAGIC native Vulkan test remains successful: a real independent app-native Android ARM64 GPU queue/fence plus offscreen 1024/1024 pixels readback. This **does not execute original CarX** and is not a first game frame.

## Explicit dependency separation

### G0 — Original game-code native Android port gate: OPEN / BLOCKED

The PC GameAssembly.dll and UnityPlayer.dll use Windows PE32+/x86-64 and include platform-specific Windows DLL/WinRT imports. Android does not directly load these as ELF/AArch64/Bionic objects. Replacing just d3d11 with Vulkan is insufficient; the game logic itself and Unity runtime are not available as native Android code. A valid strict **no-emulation** port needs authorized target-source rebuild/gameplay code and a matching Android Unity/IL2CPP target, or a fully independent gameplay implementation. A single APK bundling FEX/Wine or another compatibility stack is **still a compatibility runtime**, not the user's requested no-emulation native port.

### G1 — Android asset build/dependency gate: OPEN / BLOCKED

The source game's 808 actual Windows64 bundles and 807 referenced bundle entries were not rebuilt or loaded under Android. The 54,490 catalog IDs alone do not convert shaders, textures or serialized data across Unity platforms. Native Android asset bundles must be licensed/generated/verified for the target runtime. The Android-named substring count of 1 does not prove such assets.

### G2 — Genuine game frame/control gate: OPEN / BLOCKED

No original CarX code was executed on Android; no real original CarX scene/frame rendered; no gameplay physics or joystick input verified. Previously proven synthetic offscreen Vulkan framebuffer readback is explicitly not a genuine CarX game frame.

## New reproducible falsification tool in source

- tools/carx_v07_verified_pc_native_port_gate.py reads a user-owned v0.7 JSON locally and generates an **identity-redacted decision-only** JSON. Requires complete actual source PE/SAF and Addressables evidence. It refuses to turn synthetic GPU test success, Android substring, 807/808 bundle count discrepancy, or absence of direct EAC imports into a playable native port claim.
- tests/test_carx_v07_verified_pc_native_port_gate.py: **19 independent synthetic test and adversarial controls** for source evidence, privacy, platform classification and all G0/G1/G2 no-go requirements.
- GitHub Actions #43199150568 **SUCCESS** for all 19 synthetic tests, evidence report, and absence of private game files: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43199150568.
- The CI synthetic test output is NOT a scan of original game files; the actual source facts above are from the user's on-device v0.7 JSON.

## Engineering decision — no extra inspector APK for the next gate

Keep the already verified stable-signed v0.7 as the user APK. The missing native Android game-code runtime and platform assets are **material dependencies** which no amount of repeated PE header, catalog or Vulkan checks can supply. No user re-download, re-extraction, Termux, additional GPU test, or bundle file-by-file scan is necessary for this decision. Future work is gated on the lawful game-code and platform-asset inputs. Researching macOS and Linux Steam depots remains useful only as architecture evidence, not direct Android code.

Do not assert that native CarX PC gameplay will work or provide a fake APK without those prerequisites. Do not infer permission to redistribute copyrighted original game files from possession of a local installation.
