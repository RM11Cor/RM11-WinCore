# KERNIX backend migration — architecture decision (not a new working APK)

## Decision: start from a complete proven Android runtime
RC316–RC325 have repeatedly reached native service startup but not proved a
Windows GDI window and later caused reported full-device stalls. Installing
more isolated DLLs or rewriting the private WineServer cannot repair the
entire unverified Android host integration. The existing app is now under
an X11/game-launch quarantine for device safety.

**New engine baseline:** public GPL-3.0 source code of Bannerlator **3.1.7**,
the same family/version that was observed to run some games on the target
device. Lock the _complete_ original source tree at Git commit
`146158413f25e28f9ad04d921d0b7b806f86cc53`; never track a floating branch.

This source contains Android application lifecycle, container/prefix
management, FEXCore + native unixlib version pairing, Wine/Proton/Box64
launch, its X server/display renderer, GLES/Vulkan present paths, DXVK/
VKD3D driver managers, sound, and controllers. It is a starting architecture,
**not** a guarantee that every Windows game can run.

## Non-negotiable migration rules
1. **Don't transplant just WineServer or individual libraries.** Build the
   upstream Android runtime (Java + JNI + pinned assets) as a complete unit;
   changes to one component must pass its dependencies as a unit.
2. **Keep old KERNIX in safety quarantine** while migration proceeds in a
   separate branch. Never enable its native X11 tests merely because an
   upstream source audit or CI package succeeds.
3. **Identity/data separation:** upstream package IDs and signatures differ.
   Do not overwrite existing KERNIX data, prefixes or installed Bannerlator.
   A real KERNIX successor needs its own package/signature and an explicit
   opt-in, non-destructive migration of per-game configuration, not rootfs.
4. **Retain all third-party licenses and copyright notices.** GPL-3.0 duties
   include making modified corresponding source available and complying with
   upstream dependency licenses. Do not redistribute commercial games or DRM
   components.
5. **Unified component registry:** each Wine/Proton/FEX/DXVK/VKD3D/driver
   version is a signed/hash-attested bundle with dependencies and ABI. A game
   profile selects a compatible **existing** bundle, never patches the
   shared engine at launch. Prefixes must be kept per container/game.
6. **Three distinct proof stages:** SOURCE_PRESENT, BUILT_IN_APK,
   QUALIFIED_ON_DEVICE. A source path or CI build does not prove a playable game.
7. **Safe first milestones:** reproducible upstream 3.1.7 compile -> matching
   library/asset verification -> CI-only smoke and native ABI checks ->
   passive crash/ANR safeguards -> controlled on-device validation only after
   a reviewed host-safety gate. No heavy Proton/X11 test on the user's phone
   while device-freeze investigations remain open.

## Compatibility promise
Aim for broad compatibility with **supported** Windows games and per-game
backend choices. Games requiring unsupported anti-cheat kernel drivers,
DRM, network services, or Vulkan capabilities remain exceptions. Do not
claim 'runs every PC game'.

## What the first commit actually achieves
- Pins unmodified upstream source as a Git submodule, with a clear license.
- Validates presence of host Android runtime, FEX translation pair, DXVK,
  XServer, controller integration and per-game configuration.
- Creates reproducible source provenance and a simple public CI audit.
- **Does not** activate or package Bannerlator in KERNIX, and does not change
  the existing app's safety lockdown. Next step is adapting the upstream
  complete APK build as a new independent KERNIX engine, then rebranding UI.
