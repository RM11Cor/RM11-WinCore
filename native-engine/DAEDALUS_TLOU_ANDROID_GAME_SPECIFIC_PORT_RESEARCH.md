# KERNIX research — Daedalus Android TLOU Remastered video and per-game compatibility method

Date: 2026-11-07. Evidence: user-supplied 332.6-second video `525b0ba677f0387787f6c65d1880901f.mp4` (814×576, 30 fps); **source** cited below. Research and an offline identity-binding prototype only; no game execution or PS4 integration in KERNIX.

## Video identity, not inferred from advertising

- 00:00: `DAEDALUS / ANDROID v0.1`, `THE LAST OF US REMASTERED` launcher, `Choose game folder`, `Install from PKG`.
- 01:12–01:25: **Patches** tab, render resolution, SSAO, motion blur, depth of field, bloom, sun shadows, subsurface scattering.
- ~01:28–02:07: **Settings**, 30/60 FPS *cap*, VSync, Vulkan driver selection/import. At ~02:00 visible `Turnip Gen8 V38 Patched / Adreno 8xx`.
- ~02:16–05:20: touchscreen game footage with on-screen controller overlay. The video does **not** show compiler work, source patches, a full-game completion, or a controlled FPS comparison.

The developer is Erick Mendes (`erickmendes22`), Daedalus Emulator, Android v0.1, published 2026-11-06:
https://github.com/erickmendes22/tlou-remastered-android
https://github.com/erickmendes22/tlou-remastered-android/releases/tag/v0.1-android-bionic

**Critical edition difference:** This is **The Last of Us Remastered, PS4 2014, title CUSA00552/CUSA00556, version 01.00**. It is not **The Last of Us Part I (Windows D3D12)**. Do not assert this PS4 workflow fixes a Windows Part I/II game. The game files are user-owned and not distributed with the APK.

## Actual architecture traced to project source

1. The game’s **original PS4 x86-64 code** runs through **FEX** on ARM64 Android/Bionic.
2. A game-specialized native runtime replaces the PS4 application/system services, derived from ravencaio's Windows port, BilalReloaded/SpartanPort, and **shadPS4 video core**. PS4 GNM/GCN graphics follow the shadPS4-based Vulkan path. **This is not Wine + DXVK/VKD3D-Proton.**
3. Preparation reads the on-device game dump (`eboot.bin`, `sce_sys/param.sfo`, `sce_module/*.prx`), fingerprints it, and uses isolated staging + rename/rollback rather than modifying the player's source folder: `android/device_prepare.py`.
4. `android/tlou_patches.py` keys the known game executable by **full SELF SHA256**
   `e5f0aa322f60bd90637cc10d83de08c77885b1921084021c630e04ed3d6febf7`.
   Patches carry original-byte guards, are scoped to the exact verified profile, and fail closed for an unknown executable, even if regional CUSA matches.
5. Render-resolution changes are **32 exact code/data writes per reduced-resolution profile** rather than one 1080p→720p substitution. This accounts for configuration restoration, scene dimensions, color/depth buffers, antialiasing, and video viewport. Source: `android/PERFORMANCE_PATCHES.md`. Resolution patch success alone is not evidence of actual Android scene resolution; diagnostics must observe render targets.
6. Concrete crash remediation: `android/STATIC_SUBMESH_CRASH_20261106.md` reports source-specific invalid static collision hit submesh index, guarded before unsafe memory access; original valid-hit behavior retained. Regression tests execute the production replacement instruction bytes under Unicorn; physical Android route confirmation remains outstanding.
7. Physics correctness: `android/PHYSICS_READBACK_01_00_AUDIT_20261105.md` keeps Readback 1, uses exact layout / producer-hash-gated **selective** EOP synchronization, not a blanket Readback 2 or global GPU wait. A correct code predicate is not proof the game's GPU actually used the selected shaders.
8. Actual performance inspection: `android/EBOOT_PERFORMANCE_AUDIT_20261105.md` measured frame-thread CPU costs and concluded **no new speculative eboot patch** without current bottleneck proof. 60 FPS in the UI is a limit, not a measured performance guarantee.
9. Tested hardware is principally RedMagic 10 Pro, Snapdragon 8 Elite, Adreno 830. KERNIX target RedMagic 11 Pro, Adreno 840 requires independent Vulkan/driver/thermal proof.

Source implementation (Android is on the **non-default** development branch, not `main`):
https://github.com/erickmendes22/tlou-remastered-android/tree/tlou-ui-approval-log32-20261105
https://github.com/erickmendes22/tlou-remastered-android/blob/tlou-ui-approval-log32-20261105/android/README.md
https://github.com/erickmendes22/tlou-remastered-android/blob/tlou-ui-approval-log32-20261105/android/tlou_patches.py
https://github.com/erickmendes22/tlou-remastered-android/blob/tlou-ui-approval-log32-20261105/android/device_prepare.py

## Transfer into the independent KERNIX Windows gaming engine

**Reusable ENGINEERING METHOD, not PS4 game binaries or the PS4-specific runtime:**
- One selected game path; classify actual PE/ELF/SELF **before** selecting a backend. Read-only SHA256 fingerprint of the **actual executable**; no match by name, screenshot, title ID, or claimed game version alone.
- Bind candidate per-game component lockfile to that exact hash. Current `tools/kernix_game_profiles.py` validates disabled, offline profiles and `tools/kernix_game_preflight.py` fingerprints Windows PE. New `tools/kernix_game_profile_binding.py` combines both for a **static-only exact image check**, rejects a PS4 SELF from the Windows PE route, and **never unlocks** launch.
- Define modern-baseline source/ABI of FEX, Wine/Proton, DXVK for D3D9/10/11, VKD3D-Proton for D3D12, Turnip Vulkan; log actual feature requests and the earliest failing boundary. Version numbers cannot solve missing APIs alone.
- If a game-specific **verified** issue exists, prepare a narrowly scoped, reversible, original-byte-guarded or source-level compatibility correction with an exact fingerprint, feature gate, offline tests and matched-on-device before/after measurements. Prefer correcting modern upstream components at the actual failed layer, not global binary downgrades.
- Save original game files untouched; patches go to a separately prepared copy or carefully bounded runtime memory overlay after verified identity. Never automatically apply unverified executable patches; no silent game/wine-prefix/driver mutations.
- Separate optional future `ps4-self` plugin using a lawful, licensed PS4 service/GNM backend from `windows-pe` (Wine/DirectX). A PS4 PKG is not a Windows PE installer, and shadPS4 cannot be swapped in for VKD3D.
- Diagnostics and acceptance stages: static identity → actual guest Linux loader/FEX (current G0 still incomplete) → Windows PE/Wine → D3D/Vulkan/Android WSI → first rendered frame → repeatable game session/device metrics. Do not conflate build passing with Android gameplay.

## Licensing and truth

The Daedalus Android repository is GPL-2.0-or-later; separate subcomponents have additional licenses. **Do not copy its source/patch blobs into KERNIX without fulfilling all relevant distribution obligations and reviewing platform-specific ownership.** This research imports principles and references only; no PS4 game assets, console firmware, game code or proprietary binary patches are imported into KERNIX.

**Result of this research commit:** source-audited strategy and an offline Windows-executable exact-profile binding with synthetic tests. NOT a PS4 backend, automatic game requirement determination, running TLOU, a graphics fix, or a new release APK.
