# KERNIX — 2026-11-05 bounded Android Vulkan G1 device closeout / real-runtime handoff

## Verified *on device* from user screenshots

These are app-local Android ARM64 Vulkan WSI debug probes on the reported REDMAGIC 11 Pro. GitHub source and release hashes were verified separately; the screenshots are observational evidence, **not independently signed device attestations**.

| Gate | Device observation | Evidence |
| --- | --- | --- |
| G1 WSI initial and post-touch | 4/4 frames queued twice, `VK_RESULT=0`, no `vkCreateSwapchainKHR -3` in this probe | `evidence/g1-android-vulkan-wsi-4frame-post-touch-user-screenshot-observed-pass.json` |
| G1 visual colors | 48/48 frames queued twice including after touch, ~3157 ms; one green surface visible | `evidence/g1-vulkan-visual48-user-screenshot-48-posttouch-green-visible-pass.json` |
| G1 new SurfaceView/extent | 48/48 queued on original and new SurfaceView; 1138×813 → 1138×569; `G1_SURFACE_RECREATION_TWO_SESSION_PASS=1` | `evidence/g1-vulkan-surface-recreation-48frames-phone-screenshot-pass-20261105.json` |
| G1 bounded one-swapchain renderer loop | 180/180 queued; explicit post-touch repeat; `VK_RESULT=0`, elapsed 6224 ms, `G1_STEADY_TWO_SESSIONS_QUEUE_PASS=1` | `evidence/g1-steady180-two-sessions-user-device-screenshot-pass-20261105.json` |

The source initializes and destroys its transient Vulkan device/swapchain per test session. Therefore these gates prove **bounded swapchain creation, native queueing and recreation on the physical device at the reported UI level**. A still screenshot showing green is **not evidence of the whole sequence of animated colors**, accurate FPS, or guaranteed scan-out. Returning to a blank/green surface after an opt-in finite test is not a production failure on its own.

**Do NOT claim:** an unbounded app renderer, ongoing Android pause/resume during GPU work, DXVK or VKD3D, Wine/Proton window composition, x86 guest graphical output, or any game. The earlier `VK_ERROR_INITIALIZATION_FAILED (-3)` occurred in a different program, so absence in this isolated probe does not prove that original integration failure is repaired.

## Decision: no more frame-count-only diagnostic APKs

The bounded 4→48→180 G1 WSI **probe series is CLOSED**, subject to the narrow scope above. Do not create 360/720/1440-frame standalone versions solely to increase counters. Stop requiring the user to reinstall nearly identical diagnostics. One future functional interactive/pause-resume renderer test may be appropriate only as part of a **real integrating Android host**, with a distinct reason and reproducible failure symptom.

## Next implementation milestone: Android FEX whole Linux x86-64 process

**Blocker as of 2026-11-05:** The C3-D8C6 phone proof executes **only the first 28 original ld-linux x86-64 instructions** under FEX and returns safely; it does not complete loader relocations, TLS, libc startup, guest syscalls or a normal process exit. Existing genuine `ld-linux` + glibc full-process PASS is on **Ubuntu ARM64 Linux CI**, not Android Bionic. The existing signed Android host/FEX integration therefore cannot yet execute a whole Windows app.

The next accepted Android device artifact must (all in one end-to-end execution, not several staged synthetic tests):
1. Launch a source/hash-verified **real x86-64 dynamically linked Linux PIE** via actual original FEXCore in a separate app-private Android process; keep the original x86-64 `PT_INTERP` and `libc.so.6` bytes, pinned guest address layout and a protected rootfs.
2. Pass authentic auxv, thread stack, TLS/FS, ELF relocation and direct guest syscall ABI through correct Android/Bionic boundaries. No fake CPUState or pre-recorded stdout.
3. Show a deterministic marker **emitted by the real guest `libc` call**, actual host-observed stdout, guest exit code 0 and bounded cleanup. A nonzero exit or a CI-only test is a failure/pending result.
4. Report exact first failing stage (`elf-map`, `ldso`, `libc`, `TLS`, `syscall`, `exit`) with logs and cleanup. Restrict all paths to the app-private, hash-verified rootfs and preserve W^X and seccomp safety.
5. Produce a separately signed and individually identifiable test APK, keeping KERNIX v0.27, other APK identities, game directories and prefixes unchanged.

Only after this **real-device Linux guest process** gate may we admit a source-verified Wine/Proton runtime and test a real Win64 PE with its actual persistent window and event loop. Integrate that with Android Vulkan WSI/DXVK D3D11 in a follow-on gate; VKD3D/D3D12 only when D3D11 works. Do not shortcut to a heavyweight game or promise 100% compatibility.

## Release truth controls

- `components/registry.json` contains no accepted runtime components as of this handoff. An Android WSI debug APK is **not** a verified Wine/FEX/DXVK game-runtime bundle.
- Proven Linux ARM64 Win64 PE reference and an X11 Notepad window: `evidence/linux-arm64-fex-wine9-pe-and-notepad-reference.json`; this still cannot count as an Android game.
- Proven Linux ARM64 glibc original FEX guest: `evidence/linux-arm64-fex-g2e-real-ldso-glibc-pass.json`.
- The G1 STEADY UI displays a literal `\\n` in one result line; harmless presentation bug, not a Vulkan failure. Correct in the next integrated host UI, rather than issuing another near-identical probe.
