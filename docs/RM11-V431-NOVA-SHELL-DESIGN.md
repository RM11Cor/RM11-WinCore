# RM11-WinCore — Nova Shell v4.0.31 (clean redesign)

**Status:** Original UI foundation created on a clean branch. This is NOT an APK release or an on-device success claim.

## Clean reset

- Start from `rm11-v427-package-installer-compat`, **not** v4.0.28 / v4.0.29 / v4.0.30.
- The experimental Wine XP launcher, Android mock XP shell, imported Winlator source/RecyclerView and experimental UI workflows are **not included in this branch**.
- Existing downloadable releases and branches are retained as history for auditing; they are **withdrawn from the active development track**, not deleted from GitHub.
- Do not touch Wine/FEX binaries, prefix, storage mapping, APK signing key, game files, bundled runtime, X11 native library or graphics pipeline for a cosmetic interface change.

## Our style, not XP and not Winlator

- Identity: **RM11 / Nova Shell** — custom product styling, midnight blue/navy background with muted blue panels and one blue accent; crisp typography; no fake desktop.
- Form: full-width landscape application, safe display-cutout/system-bar insets; 215dp scrollable left rail and responsive right file workspace.
- Header: real `▶ تشغيل Windows` command, not an icon-only button.
- Rail: `C:`, `D:` permission/mount, `ملفات RM11`, Android Storage Access Framework folder chooser/last folder, diagnostics, ZIP report export.
- Files: persistent single native content view, location breadcrumbs, Back/Refresh with pointer, folder and file rows, actual file count and access/errors.
- Existing, proven v4.0.27 file-browser controller still owns navigation and Android SAF actions. UI is not tied to Wine/X11 during browsing.
- The UI deliberately does **not** claim Copy/Cut/Paste/Delete or EXE launching from file selection before their full implementations pass data-integrity and device tests. We will add each real operation deliberately, then enable its button.

## Test gates before release

1. Static source and branch comparison: only UI/controller styling changed against v4.0.27. Build unchanged. No v428+ experimental classes or Winlator files.
2. Android compile check using the existing signed APK CI workflow on a **separate candidate branch** when design approved.
3. On-device tests: 30 opens/backs, 10 C/D transitions, 10 sidebar open/close actions, no IME auto-pop, no black X11 screen during native file browsing, no overlapping old window.
4. Responsive screen width, short landscape height and navigation safe-area.
5. No APK can be called “verified on REDMAGIC” until the user performs an actual device test. The exact original APK signing identity must be checked when issuing an update.

## Next roadmap, one feature at a time

1. User visual review and adjust colors, row sizes, icons, panel proportions.
2. Preserve file navigation stability; move slow file enumeration off main thread only after profiling.
3. Implement actual single/multi-select, Copy/Cut/Paste, Rename, New Folder, Delete with confirmation; forbid symlink escapes and silent overwrites; guard recursive moves.
4. Only after shell is solid: isolated EXE launch adapter, logging and visible failure reporting without changing Wine startup.
5. Then graphics and performance components, with independent test gates.

**Design principle:** a visible action must be functional; unavailable actions should not be shown as usable controls. No copying entire other emulator's unreviewed code.
