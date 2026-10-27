# RM11 — Engine rebuild, not another black-screen patch
Updated: 2026-10-27. Working branch: `rm11-engine-rebuild`

## Nonnegotiable user constraints

- Preserve Android `applicationId=com.rm11.autocore`, existing stable signing key,
  the RM11/Nova file-manager UI, game folders on user storage, and existing prefix.
- No on-device user experiments or black-screen APK releases during reconstruction.
- Keep the last installable version **v4.0.89** untouched; this branch must never
  publish an APK merely because Java/Gradle succeeds.
- On Android 16 with targetSdk 35, do not execute code from writable app-private
  folders. Native Wine launchers and drivers must be packaged as signed APK-native ELF.
- Preserve existing user's prefix and shortcuts; new root/prefix is side-by-side,
  opt-in migration only after successful import and verified rollback.
- No assertion that Vulkan swapchain success or a viewable X11 child means
  that a Windows game frame appeared on Android.

## Evidence actually observed, not assumed

2026-10-27 physical device diagnostic ZIP, installed APK v4.0.89 code 167:
- Native X.Org reachable, but X11 root contained 13 children, 12 unmapped
  and one mapped service-size child at session end. No game window rendered.
- Wine PE-loader logs show the selected CarX Launcher and Windows DLL modules
  can be opened. Direct3D/Vulkan backend activation was not observed.
- v489 app-UID process census recorded 97 processes, 94 classified as Wine
  clients, **none of the 94 advancing CPU ticks between the last two scans**.
  Most were in other non-R/S scheduling states; this is not yet proof of
  the root scheduling cause because multiple Wine processes may be zombies.
- v478 software WSI succeeded at calling vkQueuePresentKHR in an isolated
  probe; Android surface presentation of guest/game pixels remained unverified.
- Build-time closure audit on the SHA256-pinned signed v489 APK inspected
  **3,830 archive entries** and found Wine launchers, X.Org, and FEX modules,
  but no coherent manifest and no *verified* DXVK D3D11 or hardware Turnip
  provider. This does NOT prove those DLLs never appear at runtime;
  it means their provenance and configuration cannot be certified.

## Why copy-pasting a working emulator would regress compatibility

Upstream candidate `StevenMXZ/Winlator-Ludashi` branch `4.1`
pinned review commit `1042ba5d2444900068b14137bf93a4ed6689cdd4`
is MIT-licensed but currently targets SDK 28. Our APK targets SDK 35.
The difference involves Android exec restrictions, native ABI linkage,
service lifecycle and storage permissions. Do not import its executable
rootfs strategy unchanged or replace our existing signing package name.

Alternative architectural reference: `Kachinaco/gamenative` at
`2bea2aaa54e9541873aebdf6d50e2187e6c44f30`,
GPL-3.0; no GameNative source copied. Termux:X11 Lorie already resides
in RM11 and is GPL-3.0. Review and comply with license notices
before importing more upstream code.

## Implementation order and gates

### Gate 1: Real shipped APK component proof (implemented)

- `tools/engine_closure_audit.py` inspects the exact pre-existing
  `v4.0.89` APK, including nested Wine ZIP content,
  rather than relying on old Gradle source tree.
- Rejects using Wine's builtin `d3d11.dll` as false proof of
  DXVK. A replacement engine needs signed provider manifest, source SHA
  and SHA256 of the actual DXVK DLL bytes and Turnip ICD ELF.
- The separate Action publishes a JSON **gap report only**. No APK release.
- Gate outcome on legacy APK: **BLOCKED**.

### Gate 2: One coherent source-pinned ARM64EC runtime (NOT YET COMPLETE)

- Import/compile matching Wine + FEX ARM64EC/WOW64 module pair, from the
  same build and PE ABI. Record source SHA, toolchain, ABI and SHA256.
- Provide signed APK-native Linux launchers, no app-data exec, and correct
  Wine child re-exec/IPC lifetime. No Wine cross-process zombie leaks.
- Provide a side-by-side ImageFs and Wine prefix; never overwrite user's
  existing registry/saves. Signed manifest and atomic activation/rollback.

### Gate 3: Hardware rendering to a REAL Android frame (NOT YET COMPLETE)

- Install content-addressed ARM64EC DXVK D3D11/DXGI and hardware Adreno A8xx
  Turnip ICD with the correct Bionic Vulkan loader and X11 WSI.
- Reject software `MESA_VK_WSI_DEBUG=sw` as a game-ready hardware path.
- Prove actual Android Lorie surface receives changing frames and window
  ownership, not just successful vkQueuePresentKHR return.
- Driver abort/cleanup must not kill wineserver or destroy the prefix.

### Gate 4: Release validation (NOT YET COMPLETE)

- Independent Windows-native small graphical PE with window + text, then
  a D3D11 sample demonstrating >1 distinct Android screen frame.
- Verify Wine host-child lifecycle, native CPU progression and termination.
- Hardware test on physical REDMAGIC 11 Pro. Only after these pass, consider
  CarX Street and its own compatibility requirements.
- Only after hardware proof: same packageName, stable keystore verification,
  APK upgrade migration and rollback. No claim of guaranteed CarX compatibility.

## What should not be done

- No more game-specific flags (`-force-d3d11`), FreeType
  blind redirects, random X11 window mapping, or artificial Android splash
  surfaces as substitutes for a working Wine/DXVK/Turnip chain.
- Do not conclude Wine is healthy just because the host Java Process is alive.
- Do not call old resource bundles a new engine or publish release version 4.0.90
  with the same v2.5.6 pinned Wine payload.
- Do not demand another diagnostic ZIP from the user while Gates 2–3 are open.

## Trusted sources

- https://github.com/StevenMXZ/Winlator-Ludashi/tree/4.1
- https://github.com/Kachinaco/gamenative
- https://github.com/termux/termux-x11
- https://github.com/FEX-Emu/FEX
- https://github.com/doitsujin/dxvk
- https://docs.vulkan.org/spec/latest/chapters/fundamentals.html
