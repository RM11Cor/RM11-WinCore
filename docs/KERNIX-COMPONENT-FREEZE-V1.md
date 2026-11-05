# KERNIX Component Freeze — v49150 (staged, not activated)

## Purpose
Ship one fixed component family rather than installing a new engine every time a
game is tested. Each EXE has its own persisted choices; shared signed providers
are immutable and read-only. Do not change user game content.

## Correct interpretation
- **MISSING**: no verifiable packaged provider registered.
- **PACKAGED_UNVERIFIED**: provider files exist, but no current-device evidence.
- **DEVICE_QUALIFIED**: that particular subsystem passed current-device proof.
- **DEVICE_QUALIFIED is not a universal game compatibility guarantee.**
- Online anti-cheat, DRM, online-only services and unsupported game requirements
  can still block games. Never bypass these systems.

## Fixed runtime families / dependencies

| Layer | Runtime | Hard requirements before auto-selection |
|---|---|---|
| Windows engine | Proton/Wine + FEX ARM64EC + WoW64 | matching signed runtime and writable isolated prefix; native executable proof |
| Windows window/display | win32u + winex11 + X11/Lorie | real Win32 child window and Android-visible GDI pixels |
| D3D9/10/11 fallback | WineD3D | functioning Wine GUI and supported GL path (still needs proof) |
| D3D11 high-performance | DXVK d3d11/dxgi | native Vulkan queue, WSI Present, visible D3D11 frames |
| D3D12 high-performance | VKD3D-Proton d3d12/d3d12core | native Vulkan queue, WSI Present, visible D3D12 frames |
| Native Vulkan games | device Vulkan ICD | native GPU + window-system integration proof |
| Turnip alternates | separate verified driver packs | NOT currently authenticated as selectable alternates |
| Input | Winebus, Wine HID, XInput | actual Windows XInput polling/joystick proof |
| Audio/network | Wine audio/network UnixLibs | provider-specific device tests to be added |

## Game profiles
1. Detect PE architecture, imported graphics API, anti-cheat indicators,
   engine and game folder safely; unknown metadata remains *unknown*.
2. Retain per-EXE manual overrides; never overwrite them during automatic
   inspection. No new game-private DLL injection unless signed and necessary.
3. Recommend a backend using `KernixComponentRulesV49150`, only if its
   dependencies have independent device proof.
4. In particular, D3D12 never falls back silently to WineD3D, and a detected
   anti-cheat always requires explicit compatibility review.
5. Store launch results and failure fingerprints per EXE for later tuning:
   crash, startup, frametimes, stability, memory and temperature.

## Freeze acceptance gate (do not claim this phase complete sooner)
- WineServer patched for suspected queue crash and **compiled from pinned v16**
  source, identified by ELF SHA and architecture; then signed APK package must
  contain that exact server.
- One shared, real launch plan used by GUI and library; no cross-engine
  environment, no idle WineServer death, no stale prefix success marker.
- Package audits for DXVK/VKD3D SHA-pinned binaries and GPU driver, no placeholder
  dropdowns marked installed.
- Android-visible Windows GDI frame, Vulkan GPU queue, Present, D3D11 frame,
  D3D12 frame and XInput read independently validated as appropriate.
- Per-game saved profiles persist across APK upgrades without mutating games.
- Negative tests: missing provider, unverified provider, incompatible API,
  corrupted provider, unknown EXE and unsupported protection/DRM.
- Only after this gate: begin per-game FPS, thermal and sustained stability work.

## Current scope
This change establishes inventory and recommendation contracts, **not**
a claim that all graphics providers have been bundled or made operational.
The unverified native WineServer rebuild stays independent until its binary
is validated. Do not cancel the ongoing native compiler run.
