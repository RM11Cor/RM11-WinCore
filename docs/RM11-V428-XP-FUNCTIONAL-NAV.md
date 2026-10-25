# RM11 v4.0.28 — Functional XP-style shell and genuinely smooth navigation

**Goal:** Reproduce the intended interaction from user-provided XP screenshots: one persistent desktop and file manager, true commands, fast double-click/Back/Up, no flicker or stacked old file windows, no keyboard popup on opening controls.

## User-supplied video reference — reviewed 2026-10-25

The actual 28.3-second H.264 landscape recording (2688×1216) is now available and has been visually reviewed at approximately 1-second intervals. This is an **interaction benchmark**, not evidence of a specific emulator's internals or measured FPS.

- 00–07s: XP-style desktop persists behind one non-fullscreen “Computer” file manager. The title bar, command toolbar (Up, Copy, Cut, Paste, Delete, New Folder, New File), address/breadcrumb row, left navigation tree, right sortable table, status row, bottom taskbar and green Start button remain present.
- ~08–12s: “Computer → C: → AIO Graphics Test” exploration. Contents of the right table, tree selection and breadcrumb/title all move together **inside the same frame**. Executables appear as selectable real files, with sizes and types.
- ~13–15s: another C: child folder is selected, then AIO folder is revisited. The hierarchy stays expanded without the file manager being recreated.
- ~16–21s: navigation returns to Computer, then Desktop, then Documents. Tree and right view remain synchronized, and the active taskbar caption reflects the current folder.
- ~22–27s: return to Computer and open D:. Right pane shows real folder/archive entries, with type/size; one persistent window remains visible in sampled frames.
- No distracting slide animation or stacked old explorer windows was seen in the sampled frames. **Frame-level flicker latency and guaranteed zero dropped frames were not measured**. Do not claim actual 60/120 FPS or navigation latency based on this recording.

Visual fidelity is subordinate to real functional semantics. The sample shows a **richer file manager than stock Winefile**, and merely wrapping/recoloring stock Winefile plus adding inert XP labels **cannot** deliver the required features. Use a **genuine in-process Win32 shell/file-manager component** with a navigation state model, not independent Android popup overlays:
`activeFolder`, `backHistory`, `forwardHistory`, `treeExpansion`, `fileListSelection`, `loadingState`, `runningWindowTasks`.
Drive navigation must only list real mapped volumes. Status bar counts actual items. Start menu entries must launch real installed executables and disable/hide unavailable features. Search, clipboard, file operations and startup/exit actions need separate tests.

**Video-based acceptance:** 30 cycles across Computer, C:, a nested C: folder, Desktop, Documents, D:, back/forward/up; throughout keep exactly one persistent explorer frame, update left tree + address + right pane + taskbar active label atomically, keep the desktop/taskbar stable, never summon the IME from the sidebar, never open an empty fake window, and leave no white/black flicker when content is ready. Record actual REDMAGIC render/input latency on device. Preserve last good v4.0.27 APK until its replacement passes.



## Implemented today — isolated functional ARM64 PE proof

**Status: COMPILED and VERIFIED, but not executed on REDMAGIC and not packaged into the stable APK.**

- New source: `tools/rm11_xp_explorer_arm64_v428.c` — one top-level real Windows window, persistent child file-manager panel, blue desktop, green Start button, bottom taskbar and real clock.
- Real Windows volume discovery via `GetLogicalDriveStringsW`, folder scan via `FindFirstFileW`, tree expansion, typed path + Go, Back, Forward, Up, Refresh and current-folder Search. The active folder is synchronized to list, address, task caption and left tree selection. List updates use `WM_SETREDRAW` batching.
- Actual copy/cut/paste for selected paths uses application-scoped clipboard plus Wine Shell `SHFileOperationW`; it is **not yet a system clipboard integration**. Existing destination files are rejected before operation (no silent overwrite). Delete prompts first.
- New Folder and New File use `CreateDirectoryW` and `CreateFileW(CREATE_NEW)`. Rename uses `MoveFileW`, with deferred ListView repaint. Files open via `ShellExecuteW`. Run… uses a file chooser; Start apps use Wine-provided executable names and report failures if absent.
- Real sort by name/size/date and status count (no fake drive E: unless actually mounted).
- Independent GitHub Actions compiles Windows AArch64 PE32+ with pinned llvm-mingw SHA256, checks import tables and archives its unsigned-as-app-payload EXE (not Android APK): https://github.com/RM11Cor/RM11-WinCore/actions/runs/40219687671
- **Unverified**: Wine ARM64EC loader imports, fonts and visual appearance, actual on-device double-click responsiveness, Shell file operations and UI safety under heavy/slow directories. Windows shell controls may differ in Wine's implementation.
- **Not yet implemented:** complete XP File/Edit/View/Help menu, authentic XP icons, Start task process/window enumeration, automatic app update installer, full cross-process clipboard, asynchronous directory scanning and file-operation progress. The first implementation uses a bounded synchronous folder scan; it may still block on huge folders. Treat speed targets as goals, not measurements.
- The existing stable v4.0.27 `WineAutoDesktopRunner`, Winefile, Android Activity, X11 scaling, signing assets and runtime remain untouched. DO NOT launch the isolated prototype simultaneously with the stable Winefile on the device, because competing mapped windows previously broke geometry. The next engineering step is a manually selected boot-mode switch that launches one **or** the other, with known-good mode default.

## Stable starting point and safety

- Base branch: `rm11-v427-package-installer-compat`. Do not modify its released APK, signing identity, Wine/FEX binaries, app data, mapped C/D/Z drives, X11 geometry, boot timers, or validated no-IME drawer.
- Prototype new design in its own branch. Do not publish a new APK until controls and their actions pass functional checks on actual REDMAGIC 11 Pro.
- NO fake “Start” apps, fake drives, silent destructive operations, or buttons that merely display a toast.
- Never invent E:; display only drives returned by `GetLogicalDrives()` and verified `GetDriveTypeW`, with full content accessible.
- Do not create extra top-level HWNDs in the currently stable Winefile session; Winefile should be modified IN PROCESS or replaced intentionally and gated, never augmented by cross-process popup hacks.

## Functional UI contract (no placeholders)

| UX surface | Required behavior | Win32 backend or failure gate |
| --- | --- | --- |
| Desktop wallpaper, taskbar, clock | Wallpaper fits entire X11 root; clock updates; taskbar shows real running windows and active state | One controlled Wine window + X11; owner task list from real HWNDs; background not a black root |
| Start menu | Opens/closes on button or shortcut, navigable via real pointer, keyboard ESC closes | Child of desktop surface, not extra top-level helper; consistent focus/IME |
| File Manager | Opens real drives and existing folders; double-click navigates same explorer pane | Winefile's real Pane/Entry state and filesystem enumerator |
| C:/D:/Z: (and E: if real) | Drives enumerate and open real filesystem paths | `GetLogicalDriveStringsW`, `GetDriveTypeW` |
| Left tree | Expand/collapse, synchronize selection with right contents | Real tree state, not labels |
| Right list | Names/type/size/dates correct, scroll/select without ghost rows | Real Winefile ListBox or owned-data virtual ListView, normalized UTF-16 |
| Up / Back / Forward | Up parent directory; Back/Forward use bounded distinct-location history, do not stack windows | Original process owns history; drive-root behavior defined |
| Address bar + breadcrumbs | Typed path validates and navigates; breadcrumbs reflect active location | `GetFileAttributesW`, canonicalize Windows paths, no shell command injection |
| Search | Case-insensitive filename search with cancellable background enumeration, results clickable | Separate bounded worker, no UI thread blocking |
| Copy / Cut / Paste | User-selected files/folders copied or moved with collision prompts and clipboard semantics | Wine `IDataObject` / shell APIs or verified compatible implementation; **disabled until actually functioning** |
| Delete | Real delete only after confirmation; return errors and refresh actual list | Native shell file operation API; never silently delete |
| Rename | Editable filename and actual filesystem rename, with conflict handling | Real `MoveFileExW`, correct UTF-16 paths |
| New Folder / New File | Creates real folder/file and refreshes selection; no duplicate overwrite | `CreateDirectoryW` / `CreateFileW` with `CREATE_NEW` |
| Refresh / View / Sort | Real refresh; columns and sorts reflect disk metadata | Original Winefile `refresh_child` / `set_sort_order` |
| Run… / EXE double-click | Launches selected legal local EXE with verified path and logs; displays explicit Wine failure when runtime lacks feature | `ShellExecuteExW` or controlled process service; never claim support before test |
| CMD / Notepad / WordPad | Launch verified real executable only if packaged; otherwise do **not** display as enabled | Check runtime asset and open/exit status |
| Control Panel / Settings | Real implemented settings, not decorative icons | Only show working controls |
| Quit desktop | Graceful close, preserve prefix and storage | Close session without deleting drives |
| Pointer/gamepad, keyboard | Full-window mouse, focus preserved; keyboard manual only where requested | Existing proven Lorie and IME controls |

## Smoothness acceptance, not animation gimmicks

1. When entering a folder or going Back/Up, **keep the same window and HWNDs**; change only their model content and path. No repeated creation of Winefile MDI frames, stacked folders or ghost outlines.
2. **No white/black flash**: on data refresh, suspend only affected listbox redraw via `WM_SETREDRAW(FALSE)`, update its entries and header, restore with `WM_SETREDRAW(TRUE)` in every successful completion path, then invalidate affected rect once. Do not hold redraw disabled across failure/early return.
3. Do not repeatedly enumerate drives, reload fonts or restart Wine when navigating folders.
4. Long folder scans must not freeze input; move enumerations to worker or use a cancellable list model. Maintain last painted pane until new rows are ready.
5. No slide animations that hide actual slow I/O. Aim, then **measure**: cached navigation median under 150ms, 95th-percentile under 500ms for typical small local folders; large folders get real progress/Cancel. Metrics are design targets, not achieved performance.
6. Time `mouse click -> directory enumerated -> list repainted`, log median/P95 and errors for 30 navigation cycles. Check 50 fast Back/Forward cycles and 10 multi-drive switches. No dropped input, no duplicate windows, no automatic keyboard.
7. Actual Android resolution and Winefile viewport stay full-screen. Preserve v4.0.27 screen logic untouched.
8. Native UI integration and Winefile source compatibility must be verified first; visual features only ship once the action is functional. If the underlying Wine build lacks paste/cut/search, withhold that feature, don't ship inert toolbar slots.

## Investigated Winefile implementation (audited Wine tag 11.19)

- Upstream exact commit: `455e3509b98a6919fd4ad1def4803e08c41c03b2`.
- Original `programs/winefile/winefile.c` has `scan_entry()`, `refresh_right_pane()`, `set_curdir()`, and `activate_entry()`. Scan calls `LB_RESETCONTENT` before repopulating the right pane, creating a plausible redraw gap. `WM_SETREDRAW` batching is the first source-only prototype.
- `resource.h` commands include `ID_FILE_COPY`, `ID_FILE_MOVE`, `ID_FILE_DELETE`, `ID_MKDIR`, `ID_RENAME`, `ID_REFRESH`; this does **not** prove XP Copy/Cut/Paste clipboard parity. Don't substitute Move for Cut/Paste.
- Staged source patch: `tools/patch_winefile_smooth_v428.py`, checked against pinned upstream by `tests/test_v428_winefile_smooth_patch.py`.
- **Nothing is yet compiled or integrated with the currently packaged Winefile**. Ensure exact ABI/source matching, LGPL requirements, and native device repaint correctness first.

Reference:
- Winefile original source: https://github.com/wine-mirror/wine/tree/455e3509b98a6919fd4ad1def4803e08c41c03b2/programs/winefile
- Win32 `WM_SETREDRAW`: https://learn.microsoft.com/en-us/windows/win32/gdi/wm-setredraw
- Virtual ListView item count: https://learn.microsoft.com/en-us/windows/win32/controls/lvm-setitemcount
