# Original Winlator file-manager source — preserved, NOT yet linked

Original: https://github.com/brunodev85/winlator-app
Pinned upstream commit: `8077f374ef2d54127b088de9e8cd7b4af14d9c8b` (2026-10-16)
License: LGPL-2.1 — see unmodified LICENSE next to imported source. Keep copyright and source available when distributing derivative binaries.

## What's imported

Original files in this directory are byte-for-byte textual copies from their corresponding upstream paths. Two fragment sources, their file manager list/grid, menu and supporting layout resources are preserved unmodified. They are NOT in `app/src/main` and do NOT change the production APK.

## What is still missing

Original Winlator `ContainerFileManagerFragment` extends `BaseFileManagerFragment` and imports `Container`, `ContainerManager`, `FileInfo`, `FileUtils`, `AppUtils`, `WineUtils`, icon parsing, dialogs, `RootFS`, `MSLink`, AndroidX RecyclerView, Material FloatingActionButton, themes, drawables and translations. These cannot simply be moved into RM11's build without their dependencies. Winlator manages an independent Linux rootfs/Windows prefix rather than RM11's ARM64 Wine layout. Attempting a raw paste into RM11's Android module would break the build and likely existing stable file access.

Architecture chosen: keep source UI intact in a separate Android library where practical, build a narrowly-scoped `RM11ContainerAdapter` mapping verified RM11 C:/D: directories and file operations into Winlator's UI model; never import Winlator's Box86/Box64, XServer, rootfs or replace the known-good Wine runtime. Start with an independent file-browser mode. Only after real Android build and device tests can a signed APK be released.

Acceptance: no UI placeholders, real file operations/permissions, zero automatic IME for navigation, no new Wine/X11 process for browsing, test against 5,000-directory items and 100 Back/Forward operations, verified APK signing identity and no changes to old C:/D: data. Real device outcome is not guaranteed before running it.
