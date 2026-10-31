# KERNIX — v4.90.79 unified emulator baseline

## Identity
KERNIX is a local Android Windows-game emulator project. The public UI is a clean offline launcher with a single game library, actual game cards (never hardcoded demos), a component manager and diagnostics. Android package ID remains com.rm11.autocore to preserve installed data and upgrade signature.

## Proven vs experimental
- Wine, FEX/ARM64EC, X11, DXVK, VKD3D and controller route presence are **file inventory only**, not proof of real GPU frames.
- The user's Hollow Knight result is a device-specific positive report, not a blanket guarantee.
- The Witcher 3 DX12 Vulkan device / window lifecycle is not fully working on the device. The v49075 relative paths fix and v49074 error evidence are retained; not reimplemented at UI layer.
- Native input and Vulkan must be validated independently by on-device diagnostics.

## Source of truth
- RM11GameLibraryStore: single persisted list of canonical original EXE paths; no file copying.
- RM11GameLibraryActivity: Android launcher, file picker, official diagnostics and Wine activity navigation.
- R4PremiumGalleryV49062: safe local WebView to native Java bridge; launch actions take only a validated library index, never arbitrary paths from JS.
- KernixEngineStatusV49079: read-only typed snapshot of signed available components; not a renderer proof.
- R4ManualComponentsV49069: existing per-game profiles; rejects options without installed binaries.
- RM11NativeWineActivity and NovaWineExeLauncher: unchanged native Wine/X11 rendering path.
- R4DiagnosticDownloadsV49078: MediaStore Download/ ZIP and Android downloads viewer.

## Anti-regressions
1. Do not remove native Wine/FEX assets, stored profiles or per-game original file paths as a visual cleanup.
2. Do not show fictitious install versions; do not call a GPU driver working just because the file is present.
3. Do not make ZIP save depend on the last EXE folder.
4. Do not turn touch labels into XInput claims without game proof.
5. Build/test proves packaging and source checks only. Validate device frames, controller state and Vulkan failure logs separately.

## Subsequent engineering priorities
- Isolate executable hierarchy, prefix path mapping, and X11 Vulkan WSI into testable engine adapters.
- Add real per-game runtime state and repeated game launch supervisor health checks.
- Attest frame presentation before exposing game-performance summaries.
- Add input device enumeration to the UI only after Android native HID bindings pass physical-gamepad tests.

## v4.90.80 user workflow
- Always show the authoritative KERNIX launcher even if old skin preference was false.
- Native game-info cards distinguish readable original EXE directory from file-exists only.
- Selected game has a game-specific ZIP export directly to Download without entering Wine first. The ZIP contains persisted game and engine logs; it is not a claim of current game process state.
