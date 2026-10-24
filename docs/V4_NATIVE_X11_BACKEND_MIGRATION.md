# RM11 v4: Native display backend replacement (NOT an APK release)

**Decision date:** 2026-10-24  
**Status:** Architectural change in progress; no functional replacement implemented  
**Tracker:** https://github.com/RM11Cor/RM11-WinCore/issues/9

## Device evidence — v3.1.6
The latest diagnostic archive contains two embedded Wine desktop attempts. Both pass the X11 wire connection and show wineserver survival and explorer bootstrap exit code 0. Winefile constructs Tahoma font objects; no on-device glyph rasterization or visible text is established. The user reports the visual output is unchanged in all successive releases. The archive's `wine/last-smoke.log` is the older Win32 console smoke capture, *not* the active Wine GUI log. Do not mix these evidence sources.

## Baseline and why it is inadequate
Current app owns a Java ScreenView and vendors 31 upstream `android-xserver` Java sources pinned to SHA 51e907880d4295ee3c381a593c738ca365c066fb. This core-only server does not advertise XRender, yet Wine's winex11 frontend can use XRender or alternate XPutImage paths. Therefore XRender absence alone does NOT prove the missing glyph cause. Existing tests only assert socket handshake, program launch, code presence, and APK signatures. No full-frame screenshot / text oracle exists.

## Hard architectural switch (no speculative v3.1.7 incremental X11 fix)
- Retain Wine 11, FEX, app-private prefix, signed APK identity, and all game/user data.
- Implement a **new** production display backend based on a native, proven X11 server. Evaluate and port upstream **Termux:X11** (source: https://github.com/termux/termux-x11), including source-pinned compositor, Android surface transport, native server, input events, X11 RENDER and required extensions. Native server must be packaged and started by our own application, without Termux app as a runtime requirement and without root.
- Termux:X11 is GPL-3.0; treat the license as a migration constraint. Decide publication/source-obligation integration *before* vendoring its code. Its two-piece architecture is not a drop-in module.
- Introduce `DisplayBackend` contract (start, waitForReady, framePresent, input, stop, capabilityReport), with Java core-only server retained solely for diagnostics. Select native backend for normal Windows GUI.
- Set up a source-pinned reproducible build for the native backend; verify ABI and executability under Android 16 packaged signed native libs and without `exec` from writable app storage.
- In parallel verify the **Wine process** resolves FreeType SONAME and produces a real glyph; do not infer from `librm11_freetype_core.so` Android probe.
- Verify GUI rendering with a Windows app showing **RM11 123 ABC**, distinguishable dark-on-light pixels, visible file labels for C: and Z:, and relative pointer/button responses. Record output from the actual device display/frame, not the X11 socket.
- Only then enable game-folder SAF mapping, .exe, renderer/Vulkan stack and performance tuning.

## Acceptance before next signed user APK
1. X11 endpoint handshake and native backend capability verification (not just no crash).
2. Wine client produces a visible Windows text frame, screenshot/image comparison or user-verified legibility, not only `NtGdiHfontCreate`.
3. Winefile labels for C:, Z: and known entries legible, without killing wineserver, on three separate launches.
4. Touch, drag and right-click functional across the whole screen.
5. No destructive prefix migration; same APK signing key and upgrade path.
6. Real external EXE may be tested only after items 1–5; no AAA game claims until graphics stack integrated.

## Anti-regression
- GitHub Actions success = signed APK **built**, not proof the desktop is functional.
- No `v3.1.7` user release before these gates, and no more speculative patches to FreeType aliases, delay constants or simplified X11 pixel drawing.
- Keep v3.1.5/v3.1.6 releases available for rollback and preserve their original artifacts.

## References
- https://github.com/termux/termux-x11/blob/master/README.md
- https://fossies.org/linux/wine/dlls/win32u/freetype.c
- https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/4C4XBYUL6Q2T7Y6HZ534PNTHCDK63K24/
