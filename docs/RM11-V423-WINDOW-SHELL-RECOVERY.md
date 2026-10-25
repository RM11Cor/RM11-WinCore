# RM11-WinCore v4.0.23 — Window Shell Recovery and EXE Readiness

**Status (2026-10-25): architectural recovery plan, NOT a verified release.**
**Baseline:** signed v4.0.21 works as previously user-reported, v4.0.22 screenshot exposes broken 75%-scale window plus white native popup. Preserve signature, app ID, prefix, D: mappings, FEX/Wine assets and user data.

## Confirmed code defect vs hypothesis

- CONFIRMED: v4.0.22 creates a second top-level Win32 `WS_POPUP|WS_EX_TOPMOST` helper in `tools/rm11_winefile_single_window_arm64.c` (navHost, width 104px).
- CONFIRMED: `NativeDesktopVisualEvidence.fitSingleVisibleTopLevelWindow()` aborts on `mapped != 1`; thus a second mapped X11 window can prevent geometry repair. This is a structural conflict, not a proven complete explanation of every user screenshot.
- OBSERVED: physical screenshot has a white Winefile window occupying roughly three quarters of landscape surface, black right/bottom, and a white misplaced button. Need native device X11 property/geometry data to prove actual target and rendering size.
- OBSERVED: Android startup waits for X server, wineserver/Winefile, PixelCopy readiness and animation. Removing fixed delays alone cannot guarantee 2–3s cold boot.
- CONFIRMED: winefile upstream's `create_drive_bar` creates a common-controls Toolbar with `TBBUTTON` entries inside the main Winefile frame. That is the right in-process placement for a tiny back arrow.
- NEVER use cross-process toolbar message injection or cross-process `SetParent` as a production shortcut.

## Phase 0 — Stop regression; preserve rollback

1. Archive v4.0.21 release and v4.0.22 commit with exact signing cert fingerprint, APK hash and baseline branch.
2. Remove v4.0.22 independently-mapped `navHost` popup and its message loop; no floating Android button fallback. Leave the ordinary Winefile `..` directory entry functional until proper in-process arrow exists.
3. Add CI source assertion that the Winefile controller NEVER creates a top-level popup; fail if `WS_EX_TOPMOST`, `WS_POPUP`, `navHost`, or cross-process parent tricks return.
4. Preserve currently running Winefile, verified fonts, file mappings, C/D/Z, existing `WM_MDIDESTROY` one-document policy.
5. Measure root geometry and visible X11 window count before and after screen entry. No release until full-screen device confirmation.

## Phase 1 — Single-owner display geometry

Owner: RM11 display backend (Termux:X11/Lorie), NOT an Android popup or blind keyboard shortcut.

1. Record four distinct rectangles: Android physical display / LorieView Surface / X11 root / mapped Winefile WFS_Frame. Record orientation, resize events, and X11 window ID, parent ID, map state and WM_CLASS/WM_NAME if safe.
2. Select Winefile by verified X11 identity/class and geometry, not merely `mapped == 1`. Never resize foreign application or a game. Ambiguous identity -> fail closed, log IDs and capture image.
3. On actual map/configure event request Winefile top-level maximization, then `WM_MDIMAXIMIZE` for active MDI child, then compare measured target against real X11 root. Do not send focus-stealing Alt+Space/Alt+Minus sequences once the native command works.
4. Keep X11 root and Lorie surface 1:1 in landscape. Separate Wine DPI (text readability) from physical render resolution; do not stretch a 75%-size window to hide its broken geometry.
5. Recheck on orientation/Surface change and when IME explicitly opens/closes. Never enlarge unrelated game windows. Give exact pre/post geometry diagnostics.

Acceptance: full-screen without black bars in 10 cold and 10 warm desktop launches, for C:/D:/Z: and file navigation, with no ghost frames, across app background/foreground and portrait rejection. No user data modification.

## Phase 2 — True in-process Winefile toolbar navigation

Primary implementation: patch the exact source version of `programs/winefile/winefile.c` used by our pinned Wine package, preserve LGPL attribution, reproducibly cross-compile the ARM64 PE for our Wine runtime and replace ONLY the matching Winefile PE in a source/hash-audited build.

1. Add one `TBBUTTON` with a unique command ID to the existing `Globals.hdrivebar` in `create_drive_bar()`: a small up arrow after C/D/Z, a separator and an accessible tooltip. No extra root X11 window or Android overlay.
2. Dispatch `WM_COMMAND` within the SAME Winefile process/thread. Navigate to parent using Winefile's existing internal folder state/entry handling; refresh both tree and right pane; do not manufacture an unrelated click or press on-screen Android.
3. Disable arrow at drive root, keep pointer/mouse click and keyboard activation consistent, no overlap with Shell/C/D/Z. Base position and size on actual DPI/toolbar metrics; never hardcode pixel offsets in root coordinates.
4. Do not change Wine loader, wineserver or graphics libraries for a toolbar feature.
5. Test nested folder enter/up 30 cycles, cross-drive switches, long Arabic/Unicode file names, list selection and scroll; verify no file mutation, no windows stacking.

Fallback: if pinned Winefile source cannot be rebuilt ABI-compatibly, keep native `..` folder action and hold the new arrow feature; do NOT ship a second popup disguised as final.

## Phase 3 — Deterministic boot, correct IME and focus

1. Add monotonic event spans: ActivityCreate, X11Bound, SurfaceReady, WineServerReady, WinefileProcessSpawn, MappedWFSFrame, FileListPixelsReady, CurtainOff.
2. Remove redundant fixed post-start waits when first trusted mapped/ready event arrives; keep a bounded timeout/diagnostics fallback. Defer noncritical setup after visible UI only if safe.
3. Cache idempotent font and prefix steps only after verifying previous setup success and required version/signature; never skip a necessary wineboot blindly.
4. Side drawer must not request focus/IME. Explicit keyboard action is the **only** routine that invokes keyboard show; hide when drawer enters using IME APIs, and verify fullscreen geometry after manual show/hide.
5. Report cold/warm median, p95 and per-stage times. Target minimal overhead and lower p95, NOT an unmeasured promise of two seconds.

Acceptance: three distinct run groups (cold, warm, app resume), 10 repetitions each. No accidental keyboard on drawer show, no black frame, no focus regression, same stable Winefile at exit.

## Phase 4 — EXE and first real program

Keep UI acceptance independent of Win64 execution. Then:

1. Retain pinned signed Wine ARM64EC / WoW64, FEXCore UnixLibs, executable loader, and verified wineserver process supervision; no mixed glibc/Bionic libraries.
2. Single EXE launch service for external user-chosen, authorized, unmodified Win32/Win64 files (without mandatory Steam), one child process tree per app, exact stdout/stderr/exit code, module/PE imports and crash captures.
3. First executable: small legitimate offline Win32 GUI application; next a basic OpenGL/DirectX sample; only then a legally obtained real Windows game.
4. Verify game-specific Turnip/Vulkan, DXVK, VKD3D when necessary; do not replace working Lorie/X11 for an experimental direct-scanout path until EXE GUI/input passes.
5. Add renderer selection per program later. Functional UI and mouse/IME before performance tuning; never state game support based solely on GitHub CI.

## Upstream research and licensing

- Winefile's real in-process drivebar/MDI: https://fossies.org/dox/wine-11.19/winefile_8c_source.html
- Wine upstream source mirror (LGPL): https://github.com/wine-mirror/wine
- Termux:X11 native X-server + Lorie, fullscreen, input and display scaling (GPLv3): https://github.com/termux/termux-x11
- Winlator app architecture and Wine/Box runtimes (app repository LGPL-2.1; check code per file): https://github.com/brunodev85/winlator
- Winlator Ludashi experimental DisplayX/HWC renderer and XI2 mouse, useful only after baseline UI works: https://github.com/StevenMXZ/Winlator-Ludashi/releases
- GameNative proton-wine Bionic clipboard, mouse, desktop sizing: https://github.com/GameNative/proton-wine/releases
- Internal prior design: `docs/V4_NATIVE_X11_BACKEND_MIGRATION.md`, `docs/BIONIC-ARM64EC-FOUNDATION.md`.

Before importing external source, pin exact upstream commit, scan dependency licenses, retain attribution, required source delivery, and verify static/dynamic ABI. Do not copy bundled proprietary artwork or unlicensed icons.

## No-regression release gate

CI: Java + host native + Winefile source/PE provenance tests, legal notices, APK package/name/version, fingerprint, original Wine and FEX hashes, signed executable and X11 packaged assets. Gate direct release until manual device runs confirm fullscreen, arrow, pointer, no IME auto-open, repeatable navigation and app lifecycle. Revert only affected feature if any gate fails. GitHub CI success means only that an APK was built, not that the physical-screen UI is correct.
