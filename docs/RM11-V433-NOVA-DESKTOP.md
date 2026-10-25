# RM11-WinCore v4.0.33 — Nova Desktop (inside Wine Activity)

## What the two screens are

- `RM11FileLauncherActivity`: the already-running NOVA SHELL landing page with C/D file browsing, eventually game library thumbnails. This **is not** the new desktop and remains untouched in v433.
- `RM11NativeWineActivity`: actual embedded Lorie/X11 + Wine session. It now hosts `NovaDesktopSurface` as a native full-screen overlay. **This** is the desktop the user asked for, with independent wallpaper, desktop icons, taskbar, Start, a windowed File Explorer, and real operations.
- The new overlay is not a Wine process or a Windows shell compositor. Choosing **Windows / Wine** hides the desktop overlay, exposing existing LorieView and Win32 GUI. On Android Back the existing control drawer can reopen Nova Desktop. The Wine/X11 session is not restarted on switching.
- The older `RM11DesktopStartupOverlay` remains, behind Nova Desktop, to cover Lorie while its original Winefile is booting. On future refinement, move readiness indicators into native taskbar and remove unnecessary X11 boot delays; do not disable Wine/X11 prematurely.

## Functional desktop

- Desktop folder is persistent at `appFiles/nova-workspace/Desktop`. Real folders and files appear as icons. Data is not recreated each launch.
- Desktop shortcuts for `Computer`, `File Explorer`, `C:`, `D:`, and `New Folder` open working views/actions.
- Right-click/long-press files opens actual Open folder, Copy/Cut, Rename, Delete with confirmation and Properties, as applicable.
- Desktop background long-press opens New Folder, New File, Paste, File Explorer, Refresh.
- File Explorer supports navigate into folders, Back, Up, Refresh, Computer, Create File/Folder, Paste, file context operations. C and D may be read depending on Android permission and native prefix readiness.
- File mutations are **restricted** to NovaWorkspaceFiles; no changes to Wine prefix, games, or externally located phone files; no recursive delete, silent overwrite or following symlink escapes.
- No auto Android keyboard on drawer or file navigation; keyboard appears only in a requested rename/new-file text input.
- No arbitrary EXE double-click running integrated yet. Existing Winefile in X11 may run compatible programs, and the separate EXE testing bridge has its original limitations. This is not yet a proven gaming desktop.

## Release gates

- Build CI from `rm11-v433-nova-desktop`, versionCode 116, same package and signing identity, no touching Wine runtime or Lorie assets.
- NovaWorkspaceFiles unit tests must succeed and Android Java/AAPT compiling must succeed. Compare signed APK certificate against previous trusted v2.5.6 asset; preserve package.
- Confirm on device: desktop visible immediately, icons and taskbar respond to mouse; create nested folders and rename/delete harmless files; switch to Wine then return without restarting and without a black overlay; confirm C and D permissions and screenshot sizing. The APK compiling is **not** proof these real-device tests passed.
