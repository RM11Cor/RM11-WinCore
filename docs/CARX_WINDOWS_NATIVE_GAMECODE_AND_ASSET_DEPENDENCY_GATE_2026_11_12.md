# CarX Street — original PC GameAssembly dependencies and Android asset GO/NO-GO gate

Date: 2026-11-12. Branch: carx-street-pc-port-v1. No changes to KERNIX or the separate FH5 workflow.

## Existing phone hardware proof (v0.6)

REDMAGIC NX809J Android ARM64, Adreno 840, Vulkan 1.4.295:
native independent JNI Vulkan GPU queue, fence, image transfer and 1024/1024 offscreen RGBA8 pixel readback passed on device. This is not an original CarX scene and did not run game code.

Known actual original Windows PC folder: 906 files / ~22.71 GB; Unity source header candidate 6000.3.8f1, 808 Windows64 UnityFS bundles ~19.82 GB; original GameAssembly.dll and UnityPlayer.dll are PE/x86-64; the IL2CPP metadata header is nonstandard. A signed v0.6 Android APK already exists; further synthetic graphics-demo APKs will not advance native gameplay.

## Concrete newly implemented Windows PC port input gate

Code: tools/carx_windows_gamecode_port_gate.py

- Reads user-owned original GameAssembly.dll and UnityPlayer.dll DOS/PE/COFF optional headers and bounded PE import directories.
- Reports actual architecture and DLL dependency names including Windows runtime / Steam / EAC / EOS if statically imported. Static imports are not necessarily all runtime dependencies; LoadLibrary-loaded dependencies will not all be visible.
- Parses original Addressables catalog.json (bounded to 32 MB), counts m_InternalIds Windows64, Linux64, macOS and Android names, bundle-like references and shader-name references. This measures source references, NOT a complete dependency closure, actual shader conversion or Android bundle compatibility.
- Never loads game DLL, reads anti-cheat memory, decrypts, modifies or uploads original assets.
- Do NOT treat even a PE/ARM64 code slice as Android ELF+Bionic native game.
- Independent synthetic negative tests tests/test_carx_windows_gamecode_port_gate.py, 18/18 passed in GitHub Actions #43193423694; subsequent shell-runnable, missing-game fail-closed tests passed in #43193737636.
- Termux convenience driver tools/carx_run_pc_port_gate_termux.sh auto-locates CarX Street PC under common phone storage paths and emits one small JSON report. The Python code URI is pinned to the exact commit tested by CI to avoid branch drift.

## Optional user-owned original file scan (Termux; no new APK)

Requires Termux storage permission and existing python/curl:
    termux-setup-storage
    pkg install python curl -y

One command:
    curl -fL https://raw.githubusercontent.com/RM11Cor/RM11-WinCore/carx-street-pc-port-v1/tools/carx_run_pc_port_gate_termux.sh -o "$HOME/carx_port_gate.sh" && bash "$HOME/carx_port_gate.sh"

If your extracted game is outside the automatically searched folder names, supply the path:
    bash "$HOME/carx_port_gate.sh" "/sdcard/YOUR/CarX Street"

Report output:
    /sdcard/Download/CarX_Street_Native_Port_Source_Gate.json

Upload only this small report to ChatGPT, NOT your entire installation, original DLLs or EAC files.

## Current honest GO/NO-GO

1. PC original game code remains Windows PE/x86-64 and cannot be directly loaded via Android ARM64/Bionic. Original native Android game logic from authorized source or a clean-room implementation is still REQUIRED.
2. Windows64 catalog and bundles are not Android-targeted automatically, per official Unity 6000 documentation: https://docs.unity.com/en-us/engine/6000.0/manual/assets-and-media/assets-managing-runtime/assetbundles-section/platforms
3. CarX original PC-vs-mobile FAQ says PC has changed balance, graphics and progression and no planned cross-play; official mobile native game components cannot simply be presumed compatible with PC content: https://steamcommunity.com/games/1114150/announcements/detail/4280195270688223173
4. Mac Apple Silicon and Linux Steam depots provide research paths, not original binaries inspected yet. No Mac ARM64 Mach-O or Linux ELF game code was run on Android.
5. Strict no-emulation goal means that a packaged FEX/Wine/dyld compatibility runtime, while possibly hidden inside one APK, is not a genuinely native game port.
6. Next milestone is **game-code ownership/authorized rebuild or clean-room gameplay target**, not another renderer-only prototype. Until that material dependency exists, there is no credible runnable CarX Street PC APK claim.

## Evidence

- Linux source architecture gate CI #43192244173 (16 synthetic tests): https://github.com/RM11Cor/RM11-WinCore/actions/runs/43192244173
- Mac source architecture gate CI #43190305235 (15 synthetic tests): https://github.com/RM11Cor/RM11-WinCore/actions/runs/43190305235
- PC Windows dependency and catalog gate CI #43193423694 (18 synthetic tests): https://github.com/RM11Cor/RM11-WinCore/actions/runs/43193423694
- Termux shell validation CI #43193737636: https://github.com/RM11Cor/RM11-WinCore/actions/runs/43193737636

No original proprietary CarX binary was uploaded to CI. All test passes are genuine tool/fixture results, not actual Windows game native Android executability proofs.
