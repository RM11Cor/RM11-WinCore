# RM11-WinCore — Mouse-first desktop and staged engine integration

## Product contract (v4.0.50)
- Launch always opens **the original Android app/phone file manager**.
- Its `دخول سطح المكتب` action opens one new in-app **RM11 Desktop**.
- Desktop is operated with an Android mouse / cursor and keyboard, **not controller-only or gamepad UI**. Right mouse button opens a native context menu; long press is an accessibility fallback.
- No duplicated legacy Winefile/X11 explorer or multi-activity desktop.
- Desktop shortcuts: This PC, Explorer, W: workspace, C: app files, D: SAF authorized phone, Trash, Settings.
- Bottom taskbar + Start; separate **Components** popup.
- Primary app private data, selected phone URI grants, app ID and signer are preserved on in-place update.
- **IMPORTANT**: the current cleanup APK does not include Wine/FEX/X11/graphics engines. The components popup must report **NOT LINKED** rather than pretending Windows EXEs/games run. Existing source branches preserve older runtime work for later reintroduction.

## Engine component registry and gates
| Component | Current v4.0.50 | Integration prerequisite | Proof to promote status |
|---|---|---|---|
| Main files/home + C:/W:/D: | Android browsing | Android app sandbox and SAF | File listing, safe navigation and persistence |
| Desktop shell, mouse, Start, taskbar | Native Android | Stable host Activity | Mouse secondary click, open/close/minimize window |
| Runtime supervisor and crash journal | Pending | Separate Wine session lifecycle, stop/restart | Child exit codes and failure isolation |
| FEX x86/x64 bridge | Pending | ABI-matched ARM64 runtime | Small x86_64 ELF smoke, exit code and diagnostics |
| Wine user-space | Pending | Bionic-compatible loader/prefix | Small PE64 EXE smoke; retained prefix |
| X11/Lorie window server | Pending | Session-protected display process | Actual Wine window visible and stable |
| FreeType/Win32 fonts | Pending | Secure linker path distinct from wineserver | Visible English/Arabic glyph tests without server exit |
| Turnip/Vulkan | Pending | Supported device Vulkan ICD | Separate Vulkan device/triangle probe |
| DXVK/VKD3D | Pending | Wine + Vulkan functioning | Feature-level/DirectX smoke |
| Games and controller | Pending | Verified above and input mapping | First small game, frame time + thermal stability |

## Integration boundaries
1. Do not enable legacy Wine launcher from desktop buttons before session manager is implemented.
2. **Do not silently bundle Wine or set status to ready** because an .so exists. The component popup can detect an ELF file but labels it only `bundled, not verified`.
3. Never recursively delete or reset `getFilesDir()`, the old Wine prefix or imported game folders as part of new APK installs.
4. Separate process supervisor, translation runtime, graphics driver, display server and native desktop UI. Failures in one should be visible in the diagnostics journal without white-screen loops.
5. Independent CI test and a device smoke test before connecting the next layer. Preserve prior signed APKs and reproducible releases.
6. Planned mouse interactions: click, secondary button, hover, keyboard navigation and optional double-click later; no reliance on gamepad controls.

## Why this order
Winlator-like host file browser/container setup is separated from Wine and graphics translation. The X server should be independently supervisable, and CPU architecture translation should be independently testable. This is a practical RM11 development strategy, **not a claim that Winlator, Mobox, FEX and Termux:X11 were historically authored in that exact sequence**.

## UI acceptance for this milestone
- [x] Home remains original Android files manager.
- [x] Enter desktop through one button; return to home directly.
- [x] Mouse-first small desktop icons, Start and taskbar.
- [x] Context menu on mouse secondary button and folder entries.
- [x] Component-status popup with honest unlinked / bundled / verified distinction.
- [ ] REDMAGIC device confirmation of secondary mouse click and popup placement.
- [ ] Wine/FEX/X11 integration (explicit later milestone).
