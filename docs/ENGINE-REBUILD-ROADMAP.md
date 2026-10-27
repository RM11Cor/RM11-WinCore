# RM11 — Engine rebuild, not another black-screen patch
Updated: 2026-10-27. Working branch: `rm11-engine-rebuild`

## Nonnegotiable user constraints

- Preserve Android `applicationId=com.rm11.autocore`, existing stable signing key,
  the RM11/Nova file-manager UI, game folders on user storage, and existing prefix.
- No on-device user experiments or black-screen APK releases during reconstruction.
- Keep the last installable version **v4.0.89** untouched; this branch must never
  publish an APK merely because Java/Gradle succeeds.
- On Android 16 with targetSdk 35, do not execute code from writable app-private
  folders. Native Wine launchers and drivers must be packaged as signed APK-native ELF.
- Preserve existing user's prefix and shortcuts; new root/prefix is side-by-side,
  opt-in migration only after successful import and verified rollback.
- No assertion that Vulkan swapchain success or a viewable X11 child means
  that a Windows game frame appeared on Android.

## Evidence actually observed, not assumed

2026-10-27 physical device diagnostic ZIP, installed APK v4.0.89 code 167:
- Native X.Org reachable, but X11 root contained 13 children, 12 unmapped
  and one mapped service-size child at session end. No game window rendered.
- Wine PE-loader logs show the selected CarX Launcher and Windows DLL modules
  can be opened. Direct3D/Vulkan backend activation was not observed.
- v489 app-UID process census recorded 97 processes, 94 classified as Wine
  clients, **none of the 94 advancing CPU ticks between the last two scans**.
  Most were in other non-R/S scheduling states; this is not yet proof of
  the root scheduling cause because multiple Wine processes may be zombies.
- v478 software WSI succeeded at calling vkQueuePresentKHR in an isolated
  probe; Android surface presentation of guest/game pixels remained unverified.
- Build-time closure audit on the SHA256-pinned signed v489 APK inspected
  **3,830 archive entries** and found Wine launchers, X.Org, and FEX modules,
  but no coherent manifest and no *verified* DXVK D3D11 or hardware Turnip
  provider. This does NOT prove those DLLs never appear at runtime;
  it means their provenance and configuration cannot be certified.

## Source-level ABI truth from the exact shipped v4.0.89 APK

The byte-for-byte checked release APK (SHA256
`1f6c511e6949080e9ec41b6b08ae724cccc49d5c10491db16db9bb32371e34e8`)
has now passed the independent header/metadata audit:

- `libwineprobe.so`, `libwineserverrm11.so`, `libwine_winex11.so`
  and `libXlorie.so` are AArch64 ELF64 binaries, machine 183.
- `libwow64fex.dll` is PE32+ for ARM64, machine `0xAA64`.
- `libarm64ecfex.dll` is a **final linked hybrid ARM64EC PE** with
  COFF machine `0x8664` (AMD64) and present CHPE load-configuration
  metadata, version 1. This is **correct**, not an architecture error.
  ARM64EC `0xA641` is associated with intermediate object files, not
  the normal linked final DLL header. Do not "fix" this DLL by swapping
  it for an ARM64-only image.
- `tools/pe_chpe.py` checks the actual mapped PE Load Config
  `CHPEMetadataPointer`, not a filename or string occurrence.
- This is **structural ABI compatibility only**. It does not prove
  the Windows PE executes, Wine/FEX lifecycle is correct, or GPU frames
  reach the Android screen.

The missing release readiness proof remains the coherent DXVK and
hardware Turnip closure, native child-process lifecycle, and real
Android frame presentation. No more game APK iterations are justified
until those components are proven.

### New integrity rule

The old `.verified-bundle` marker alone was insufficient: installed
DLLs could be overwritten while leaving the marker intact. The new
`EngineInstalledTreeVerifier` compares every staged PE/data byte with
the SHA-pinned original ZIP and rejects missing or extra files, symlinks
and tampered content before even reusing an installed engine directory.
It cannot silently overwrite a user's existing Wine prefix.

### Existing process evidence is concerning but not a root-cause proof

The v4.0.89 device report recorded 97 same-app-UID Linux processes:
94 categorized as Wine clients, none advancing CPU ticks between two
20-second snapshots, and 86 states not classified as running/sleeping
by our older process census. Those "other" states were not subdivided
(`Z` zombie, `T` stopped, etc.), so attributing the entire failure
to zombie-process accumulation would be premature. The future
coordinated process supervisor must handle re-exec, SIGCHLD and child
reaping explicitly, rather than continuing to patch graphics blindly.

### Supporting verified upstream references

- Microsoft: https://learn.microsoft.com/en-us/windows/arm/arm64ec
- Wine loader `has_chpe_metadata()`: Wine `dlls/ntdll/loader.c`
- FEX build example with `llvm-readobj --coff-load-config`:
  https://github.com/The412Banner/Nightlies/blob/main/.github/workflows/fexcore-linux-stable.yml

## Why copy-pasting a working emulator would regress compatibility

Upstream candidate `StevenMXZ/Winlator-Ludashi` branch `4.1`
pinned review commit `1042ba5d2444900068b14137bf93a4ed6689cdd4`
is MIT-licensed but currently targets SDK 28. Our APK targets SDK 35.
The difference involves Android exec restrictions, native ABI linkage,
service lifecycle and storage permissions. Do not import its executable
rootfs strategy unchanged or replace our existing signing package name.

Alternative architectural reference: `Kachinaco/gamenative` at
`2bea2aaa54e9541873aebdf6d50e2187e6c44f30`,
GPL-3.0; no GameNative source copied. Termux:X11 Lorie already resides
in RM11 and is GPL-3.0. Review and comply with license notices
before importing more upstream code.

## Upstream implementation ports under review (source paths)

Source review (no binaries or GPL source transplanted yet) identifies the
specific working components that must be made coherent:
- `com.winlator.cmod.xenvironment.components.GuestProgramLauncherComponent`
  from MIT-licensed Winlator Bionic 4.1: handles Guest Wine execution,
  emulation-module extraction and per-container settings. It references
  `Container`, `XEnvironment`, `ImageFs`,
  `FEXCoreManager`, content profiles and rootfs configuration.
  Copying this class alone would not provide that dependency chain.
- `com.winlator.cmod.XServerDisplayActivity` constructs a full
  `XServer` rendering backend and installs graphics drivers,
  DXVK wrappers and Win32 components in a coordinated container.
  The class is thousands of lines; grafting UI wholesale would replace RM11.
- New RM11 will bridge its file UI into a reusable runtime session and
  guest-renderer host, **not** transplant Winlator's entire activity.
  Existing Termux:Lorie display remains available only when the hardware
  presentation path is confirmed.
- The side-by-side signed data installer now exists at
  `app/src/main/java/com/rm11/autocore/engine/EngineDataStager.java`.
  It verifies archive bytes, rejects ELF/native executables in writable
  engine data, checks PE headers for new Windows DLLs, and atomically
  promotes versioned data without overwriting the legacy prefix.
  It does not yet activate a new Wine engine, import binary packages or
  prove game drawing.

## Implementation order and gates

### Gate 1: Real shipped APK component proof (implemented)

- `tools/engine_closure_audit.py` inspects the exact pre-existing
  `v4.0.89` APK, including nested Wine ZIP content,
  rather than relying on old Gradle source tree.
- Rejects using Wine's builtin `d3d11.dll` as false proof of
  DXVK. A replacement engine needs signed provider manifest, source SHA
  and SHA256 of the actual DXVK DLL bytes and Turnip ICD ELF.
- The separate Action publishes a JSON **gap report only**. No APK release.
- Gate outcome on legacy APK: **BLOCKED**.

### Gate 2: One coherent source-pinned ARM64EC runtime (NOT YET COMPLETE)

- Import/compile matching Wine + FEX ARM64EC/WOW64 module pair, from the
  same build and PE ABI. Record source SHA, toolchain, ABI and SHA256.
- Provide signed APK-native Linux launchers, no app-data exec, and correct
  Wine child re-exec/IPC lifetime. No Wine cross-process zombie leaks.
- Provide a side-by-side ImageFs and Wine prefix; never overwrite user's
  existing registry/saves. Signed manifest and atomic activation/rollback.

### Gate 2A: New session-owned Wine lifecycle (HOST TESTED; ANDROID NOT INTEGRATED)

Source modules added without modifying the installed v4.0.89 application:

- `EngineOwnedProcessSession.java`: starts only SHA256-pinned APK-native
  `libwineprobe.so` / `libwineserverrm11.so` entrypoints; explicit
  environment, pipe draining capped at 32 KiB, orderly stop/wait/force
  termination of **directly owned** Java Process children.
- `tools/engine_native_session_supervisor.c`: a standalone Linux
  supervisor prototype which configures `PR_SET_CHILD_SUBREAPER`,
  forks a Wine native launcher into an **owned process group**, reaps
  its actual children with `waitpid()`, and shuts down that group
  on exit or request. It refuses arbitrary paths and requires the
  caller to supply an APK-native-directory path.
- Tests prove it can reap a forked **orphan descendant** and leave a
  separate unrelated process untouched. Host GCC `-Werror` and
  executable process tests run in dedicated GitHub Actions.
- Current source contains no Android package configuration for
  deploying the native supervisor. It has not been linked to Wine,
  FEX, X11 or the app. **No APK is released.**
- Android NDK linker layout, executable-from-signed-APK restrictions,
  SIGCHLD ownership, prefix IPC and compatibility with Wine `execv`
  remain an explicit future integration gate.

**Important Linux process limitation:** a subprocess in `Z` zombie
state is reaped exclusively by its parent with `waitpid()`, or by an
eligible subreaper *after its parent exits*. Our supervisor cannot
reap a zombie still owned by another living Wine process. The latest
device report observed 86 "other" process states, but old diagnostics
did not enumerate `Z` versus `T`/`D`. No claimed verified root
cause or fix for all 86 processes follows from these host-only tests.

### Gate 2B: Native Android ELF and Java ownership bridge (NDK BUILT)

The vNext native supervisor was cross-compiled (without installing an APK)
using Android NDK `27.2.12479018`, target
`aarch64-linux-android29`, PIE dynamic executable with
Android's `/system/bin/linker64`. The output is deliberately
named `librm11_engine_supervisor.so` for future Android
`nativeLibraryDir` packaging under API 35; its four LOAD segments
have 16 KiB alignment. SHA-256 of the verified host-built candidate:
`a51537de92bb059ec328c3509b25c6cd4bb0c310aa648ccbf853d4d1f4df0ba8`.

- Static NDK/ELF verification: GitHub Actions run
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40566578077
  reported `ELF_STRUCTURE_READY_FOR_ANDROID_DEVICE_PROOF`.
- Java `EngineOwnedProcessSession.startSupervisedWine()`
  validates both the supervisor and Wine ELF SHA-256, injects the
  signed-native-library root, and starts the Wine native loader as a
  **direct child of the subreaper** instead of independently launching
  uncontrolled processes.
- Host end-to-end test:
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40567111333
  passes a harmless executable stub through
  Java -> host Linux native supervisor -> child, while refusing a
  mismatched supervisor SHA, mismatched Wine SHA, and untrusted native
  directory override. Tests: `RM11_ENGINE_JAVA_NATIVE_BRIDGE_PASS checks=9`.
- The native Android supervisor is **not installed** into any signed APK
  and has **not been run** on the REDMAGIC device. The vNext Java bridge
  is separate from the legacy `WineShellDesktopRunner`.
  Tests on glibc Linux do not establish Android Bionic's process
  lifecycle or Wine GUI compatibility. Engine activation stays disabled.
- The supervisor only reaps direct children and orphan descendants
  actually reparented to it. Zombie grandchildren attached to a living
  parent remain outside its waitpid() responsibility.
- Next integration requires APK-native packaging with matching signed
  SHA manifest and **real Wine/FEX launch lifecycle**, then combined
  Turnip/DXVK/X11 frame presentation. No new user test yet.

### Gate 2C: Same-signature APK packaging (CI VERIFIED; STILL INACTIVE)

GitHub Actions run
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40569312769
successfully cross-compiled the NDK AArch64 PIE native process
supervisor and placed only that ELF at
`lib/arm64-v8a/librm11_engine_supervisor.so`
inside a **private, temporary internal candidate derived from the
exact SHA-pinned v4.0.89 APK**. The internal APK was aligned and re-signed
using the existing RM11 PKCS12 release key GitHub Secrets.
`apksigner verify` confirmed the candidate signature, and
the certificate SHA-256 matched the already-published v4.0.89 release.
`aapt dump badging` confirmed unchanged application identity.

A conservative ZIP comparator confirmed:
- Existing packaged Android manifest, UI resources and embedded Wine
  components were **not changed** (entry counts/CRCs and cryptographic
  hashes of all five crucial Wine/X11 resources).
- Exactly **one** file was added: the new native supervisor ELF, packed
  uncompressed and checked against its NDK-built SHA-256.
- The supervisor was never activated. The internal candidate APK was
  **deleted after checking**. CI artifact contains only JSON proof
  reports. No published installable APK and no new user device test.

**Important limitation:** this isolated repackaging validation only
proves the native ELF can be added while retaining identity and contents.
It uses the v4.0.89 APK's *existing* Java code, not an Android build of
the new vNext Java process bridge. Therefore the signed internal
candidate is **not** a complete vNext engine or a usable game fix.
Source-integrating the bridge with the new engine, verifying its signed
manifest, and demonstrating Bionic Wine child re-exec on a real Android
device remain open gates. It cannot substitute for DXVK, Turnip and
Android frame presentation.

### Gate 2D: Android Gradle Java + native source-built AAR (CI PROVEN)

Separate Gradle project `:enginebridge` now compiles the three actual vNext
Java engine classes out of the existing RM11 repository source tree.
The app's `app/build.gradle` includes the Android library as a
project dependency and excludes those engine sources from its own
Java source set to prevent duplicate classes.

GitHub Actions run
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40570775819
was verified `completed/success`:
- Android Gradle 8.10.1 / Gradle 8.11.1 compiled the actual source
  into a release Android AAR. `classes.jar` includes the engine's
  `EngineOwnedProcessSession`,
  `EngineDataStager` and
  `EngineInstalledTreeVerifier`.
- The AAR includes exactly one AArch64 native executable
  `jni/arm64-v8a/librm11_engine_supervisor.so`,
  with the exact NDK ELF SHA-256
  `a51537de92bb059ec328c3509b25c6cd4bb0c310aa648ccbf853d4d1f4df0ba8`.
- Android compilation exposed unsupported Java `Files.readString`/
  `writeString` calls in the prototype; both were replaced with
  byte-based NIO read/write compatible with Android's API surface.
- The vNext engine bridge is not yet enabled from the legacy activity
  or the Windows game launcher. No APK was built or published.

To validate the actual APK app source compilation rather than only
the AAR, `rm11-engine-app-java-linkage.yml` builds the exact
previously pinned GPL Termux:X11 Lorie AAR source, then runs
`:app:compileDebugJavaWithJavac` with the new
`:enginebridge` dependency. The source-build gate must
distinguish this from true device execution or DXVK/Turnip rendering.
The action publishes JSON report only; it does not release an APK.

### Gate 2E: Source-built Android APK with original Wine runtime bytes (CI VERIFIED)

The full source APK package build now passes with all essential historical
Wine launchers and bundled Wine/FEX data intact:

- https://github.com/RM11Cor/RM11-WinCore/actions/runs/40575211741
  originally assembled the Android Debug APK with the vNext engine AAR,
  but **failed the real runtime-completeness question**: the new APK
  lacked `libwineprobe.so`,
  `libwineserverrm11.so` and
  `assets/runtime/rm11-wine-stack.zip`.
- A new fail-closed source gate is in
  `tools/stage_pinned_legacy_runtime.py`, which fetches from the
  **SHA256-locked v4.0.89 published APK only** and stages the exact
  Wine client ELF, wineserver ELF and old Wine stack ZIP inside the
  source-built app before its Android Gradle packaging.
- `tools/verify_engine_source_apk.py` fails if these
  artifacts are missing, if the supervisor ELF changed, or if the
  first three runtime bytes differ from the signed previous release.
- Run https://github.com/RM11Cor/RM11-WinCore/actions/runs/40576790730
  completed **success**. The generated Android Debug APK contains
  X11/Lorie, vNext NDK supervisor, both original Wine native ELF
  binaries and the original Wine/FEX stack data, with all three
  historical Wine components **SHA256-equivalent** to the signed
  v4.0.89 APK.
- The APK remains **debug-signed, discarded after CI checks, and was not
  released or installed**. This is source-build/package provenance
  proof, **not a migrated engine** or a rendering fix.
- Missing future proof: sign the rebuilt app with the stable release
  certificate after a real compatible engine closes DXVK/Turnip/X11,
  and then demonstrate supervised Wine/FEX process lifecycle on
  Android. No claim of game compatibility or black-screen resolution.

### Gate 2F: Signed process identity, clean supervisor and shared Wine game plan

Source changes on `rm11-engine-rebuild` (no new user APK):

- `tools/build_engine_runtime_manifest.py` derives an APK-embedded
  `assets/engine/engine-native-manifest.json` exclusively from
  the known SHA256-pinned v4.0.89 native Wine/FEX payload and the current NDK
  supervisor ELF. No manifest is trusted from game files or writable ImageFs.
- The source-built Android app contains the manifest with exact
  supervisor, Wine client, wineserver and Wine/FEX stack ZIP hashes.
  `tools/verify_engine_source_apk.py` refuses absent or
  mismatched signed component entries or activation declared ready without
  hardware proof. Six host regression tests passed on
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40578854206.
- `EngineVNextNativeManifestGate` validates the
  installed APK-native ELF files against this bundled asset at runtime.
  It always rejects engine activation until the actual hardware frame
  and Wine/FEX/renderer session criteria are met.
- A significant dynamic-loader contamination hazard is now fixed:
  `EngineOwnedProcessSession.startSupervisedWine()`
  removes Wine `LD_PRELOAD` and
  `LD_LIBRARY_PATH` from the **supervisor** environment.
  The native supervisor restores both strictly in its **child after
  fork()** and just before executing Wine. Reserved control-variable
  overrides and `LD_AUDIT`/`LD_DEBUG` are
  rejected. The C supervisor also rejects startup if either raw
  linker variable accidentally leaked into its own process.
- Latest host reaper run
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40579277805
  passed the extra raw-linker-env rejection test and 12 Java-to-native
  bridge checks (including verifying Wine child sees its own library path).
- `NovaWineExeLauncher.prepare()` is extracted from the
  old direct game launch method to produce **one** verified Wine/FEX/X11,
  prefix, driver and D3D launch configuration. The legacy `start()`
  method delegates to `prepare()` and keeps its original
  process creation and post-start logging behavior.
- `EngineVNextWineHandoff` consumes this identical plan,
  compares Wine's executable against the signed manifest and uses the
  protected Java->native supervisor handoff; it is deliberately
  **inaccessible to ordinary game launch** because activation remains OFF.
  The regular launcher continues working exactly as before.
- EngineHardwareWsiPolicy explicitly rejects MESA_VK_WSI_DEBUG=sw,
  including case/multi-token variants, and the old v479 software-Vulkan
  proof flag. **Passing this negative filter is not evidence that hardware
  WSI is ready**. Seven independent host checks passed on
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40581289718.
- The full Android application source compilation and ephemeral debug APK
  packaging **passed** with this shared Wine plan and new WSI filter on
  https://github.com/RM11Cor/RM11-WinCore/actions/runs/40581211286.
  It included the APK-signed component manifest, Wine loader, wineserver,
  original Wine/FEX assets, native supervisor, and Termux:X11; release
  remains blocked and the ephemeral APK was deleted after audit.
- None of the above proves Wine process progress, genuine GPU rendering,
  physical Android framebuffer presentation or CarX compatibility.
  Native device integration and DXVK/Turnip closure remain unfinished.

### Gate 2G: DXVK/Turnip provider closure (PROVEN BLOCKED ON CURRENT APK)

The signed v4.0.89 APK was re-audited byte-for-byte with a more precise
graphics gate on
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40583122004.
Eight host regression tests passed, and the original source APK returns
`BLOCKED_NO_SIGNED_PROVIDER_MANIFEST`, not a false DXVK success.

The new `engine_graphics_provider_audit.py` independently checks:
- Original upstream DXVK `d3d11.dll` and
  `dxgi.dll` must have a content-addressed source
  manifest, unambiguous files under
  `assets/engine/providers/dxvk/x64`, and genuine
  PE32+ x86-64 executable headers. Wine builtin DLLs or filenames are
  **not** DXVK proof.
- A native Turnip provider must be under the signed APK
  `lib/arm64-v8a` and have a matching SHA-256 and
  AArch64 ELF64 DYN header. Its provenance must identify the Mesa source
  commit and Android/Bionic target (not glibc).
- A manifest `wsi: hardware` assertion cannot prove
  that a real Vulkan queue presented an X11 game window on an Android
  `Surface`. Runtime frame proof remains independently
  unavailable.
- The vNext source APK's packaging audit now explicitly reports
  `graphics_provider_static_gate` and keeps
  `graphics_device_frame_proof=UNVERIFIED`.
- The separate upstream source-build job
  `rm11-engine-build-dxvk-source.yml` pins signed
  DXVK `v2.7.1` to commit
  `c3dd74be6baec53786d4e064a572185b70347a17`
  and builds native Win64 `d3d11.dll` and
  `dxgi.dll` with MinGW. The outputs are verified as
  x64 PE32+ with content SHA before they may be considered for future
  integration. The build is separate from the app: no active renderer,
  prefix override or APK release is enabled by it.

**Outstanding:** Upstream DXVK may require
`VK_KHR_maintenance5` and other Vulkan driver features;
neither a correct PE header nor successful cross-compilation proves that
our Android Turnip ICD exposes them. A Bionic KGSL-native provider and
real X11 WSI to Android pixels must still be implemented and tested.
Do not modify system/vendor partitions or replace the phone's global
Vulkan driver. Keep this as an isolated app-native provider.

### Gate 2H: DXVK + Turnip built from upstream; Android app namespace still blocked

DXVK 2.7.1 signed-release source commit
c3dd74be6baec53786d4e064a572185b70347a17
successfully produced genuine Win64 PE32+ dxgi.dll and d3d11.dll. The
source/architecture/hashes and binaries are retained as a verified,
non-APK integration artifact in
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40584764808 .

Mesa 26.2.0 exact archive SHA256
efd4bb08cdb7c365a812cd4e6c9202ab55b2f22cdcd13c7d6c4f9647b799a4ef
cross-compiled all 914 targets under Android NDK R27, AArch64 KGSL,
and linked libvulkan_freedreno.so. The result has an AArch64 ET_DYN
ELF header and Bionic libc.so dependency, not glibc.
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40585326064

**Critical compatibility gap:** the Turnip shared library has
DT_NEEDED dependencies on libhardware.so (private Android HAL /
VNDK-SP) and libc++_shared.so, plus other native libraries.
Android targetSdk 35 app linker namespaces are not necessarily
allowed to load libhardware.so. Therefore simply putting the
new Turnip driver into the APK would likely fail at dlopen() before
any Vulkan device or game render attempt.

The Turnip ABI policy now returns
BLOCKED_PRIVATE_AOSP_LIBHARDWARE_DEPENDENCY when it finds that
dependency and never claims app-native loading succeeded.
Reference: Android Bionic private library restrictions:
https://android.googlesource.com/platform/bionic/+/HEAD/android-changes-for-ndk-developers.md

Still required: resolve the native app namespace HAL dependency
without rooting or overwriting /vendor; package the correct
libc++_shared.so from the matching NDK; verify Vulkan physical
Adreno device enumeration, instance extensions, and X11 WSI through
the actual RM11 private display; connect source-built DXVK to Wine/FEX;
and demonstrate real rendered guest pixels visible on Android.
A successful build or software WSI submission is NOT such proof.
The game activation gate remains OFF and no APK is released.

### Gate 3: Hardware rendering to a REAL Android frame (NOT YET COMPLETE)

- Install content-addressed ARM64EC DXVK D3D11/DXGI and hardware Adreno A8xx
  Turnip ICD with the correct Bionic Vulkan loader and X11 WSI.
- Reject software `MESA_VK_WSI_DEBUG=sw` as a game-ready hardware path.
- Prove actual Android Lorie surface receives changing frames and window
  ownership, not just successful vkQueuePresentKHR return.
- Driver abort/cleanup must not kill wineserver or destroy the prefix.

### Gate 4: Release validation (NOT YET COMPLETE)

- Independent Windows-native small graphical PE with window + text, then
  a D3D11 sample demonstrating >1 distinct Android screen frame.
- Verify Wine host-child lifecycle, native CPU progression and termination.
- Hardware test on physical REDMAGIC 11 Pro. Only after these pass, consider
  CarX Street and its own compatibility requirements.
- Only after hardware proof: same packageName, stable keystore verification,
  APK upgrade migration and rollback. No claim of guaranteed CarX compatibility.

## What should not be done

- No more game-specific flags (`-force-d3d11`), FreeType
  blind redirects, random X11 window mapping, or artificial Android splash
  surfaces as substitutes for a working Wine/DXVK/Turnip chain.
- Do not conclude Wine is healthy just because the host Java Process is alive.
- Do not call old resource bundles a new engine or publish release version 4.0.90
  with the same v2.5.6 pinned Wine payload.
- Do not demand another diagnostic ZIP from the user while Gates 2–3 are open.

## Trusted sources

- https://github.com/StevenMXZ/Winlator-Ludashi/tree/4.1
- https://github.com/Kachinaco/gamenative
- https://github.com/termux/termux-x11
- https://github.com/FEX-Emu/FEX
- https://github.com/doitsujin/dxvk
- https://docs.vulkan.org/spec/latest/chapters/fundamentals.html


### Gate 2I: App-namespace candidate without private legacy HAL (SOURCE/ELF CI VERIFIED)

Mesa `-Dandroid-stub=true` creates temporary *link-time* stub shared
libraries `libhardware.so`, `libnativewindow.so` and `libsync.so`.
They are not driver dependencies to copy into an Android APK: the Mesa
source README explicitly says the stubs are not installed. Actual Android
`libnativewindow.so` and `libsync.so` are public NDK libraries;
`libhardware.so` is a private platform HAL dependency.

The new source-only patch `tools/patch_mesa_android_app_namespace.py`
replaces the temporary shared `libhardware.so` dependency with an
in-tree *static* fail-closed legacy HAL implementation. It sets the module
pointer NULL and returns `-ENOSYS` for `hw_get_module()`, preventing
the obsolete gralloc module path from being falsely treated as present.
It does **not** fake working gralloc or provide a Vulkan surface.

The completed source-build GitHub Actions run
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40588147484
passed all 10 source/ABI regression tests, compiled the full Turnip driver,
and verified that the final ELF has NO DT_NEEDED for libhardware.so and
NO undefined hw_get_module symbol. The source-built artifact is retained
for the next gated stage, with 8 remaining DT_NEEDED dependencies including
NDK libc++_shared.so. The pinned source and patch audit tested exact Mesa
source anchors, and would fail if
the Android shared ELF still needs private `libhardware.so` or has
unresolved `hw_get_module`, and retains dynamic symbol/DT_NEEDED evidence.
This is a **verified compile/link namespace improvement candidate**, NOT proof of
app `dlopen`, Adreno GPU access, gralloc buffers, or X11/Android frames.

Before enabling the renderer we still must integrate a real, verifiable
IMapper5/Gralloc backend for application processes, verify the exact
device's Vulkan loader/namespace path and A8xx features, and show
distinct guest-rendered frames in the Android Surface. No APK release.

**Upstream graphics-driver patch licensing check:** WinNative-Emu/Drivers
currently includes a GPL-3.0 top-level LICENSE even though its README
describes itself as MIT; individual files may carry independent SPDX
licenses. Any IMapper5 or UBWC implementation must therefore be
reviewed file-by-file and attribution/license obligations respected
before importing source. Source research alone does not authorize a
blind transplant.

The next engineering gate is genuine IMapper5/Gralloc/UBWC integration
and proving an Android app process can dlopen and enumerate this driver.
The fail-closed legacy HAL fallback deliberately does NOT impersonate
functional gralloc. The matching NDK libc++_shared.so must be packaged
before any runtime loader proof. No APK is published.


### Gate 2J — Pinned Mesa 26.2.0 Turnip with IMapper5 (CI LINK VERIFIED)

The actual Mesa 26.2.0 KGSL AArch64/Bionic build now includes the
IMapper5 backend from WinNative-Emu/Drivers pinned at
`c71f600a2977a141f21a922c9ed2e14fb09b13d3`.
The C implementation carries its own SPDX MIT header; the upstream
repository also has a GPL-3.0 top-level LICENSE. File-level copyright
and licensing must be reviewed again before release.

The first integration correctly **FAILED** because the external backend
targeted later Mesa `basic_info.layer_count` and `alloc_size` fields.
A fail-closed, tested compatibility transform removes only that
late-Mesa metadata block for pinned Mesa 26.2.0, making no claim of
multilayer layout support.

The corrected GitHub Actions run
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40589960744
completed **success**:
- 17 source/ABI regression tests passed.
- The resulting `libvulkan_freedreno.so` contains compiled
  `u_gralloc_aimapper_create`, verified in the ARM64 object and final ELF.
- The ELF is Bionic ARM64 and no longer has a `libhardware.so`
  DT_NEEDED dependency; the old `hw_get_module` legacy reference is not
  undefined.
- The pinned upstream and transformed file SHA256 plus Mesa ABI proof
  are retained in the source build artifact.
- No physical Android SP-HAL `libvndksupport.so` access, mapper
  enumeration, UBWC allocation, Vulkan surface, or changing Android
  game frame was proven. No APK was built or published.

### Gate 2K — Source-pinned Android libadrenotools loader hooks (LINK VERIFIED)

Pinned official `bylaws/libadrenotools` commit
`8fae8ce254dfc1344527e05301e43f37dea2df80`,
BSD-2-Clause, compiled via NDK r27 for Bionic ARM64.
GitHub Actions
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40590287552
completed **success** and independently audited the 5 ARM64 shared
libraries `libadrenotools.so`, `libhook_impl.so`,
`libmain_hook.so`, `libfile_redirect_hook.so`, and
`libgsl_alloc_hook.so`.

**Critical architecture warning:** libadrenotools works inside the
*process that opens libvulkan*. Running it only inside RM11's Java
activity does not intercept libvulkan opened in separate supervised
Wine child processes. We must identify and instrument the actual Wine
Vulkan Unixlib/dlopen process, preserve driver namespace inheritance
and re-exec semantics, and verify the custom Turnip ICD actually wins
over the system ICD in that process. The `hookLibDir` must resolve to
the signed `nativeLibraryDir`; normal app read/write storage is not an
APK-native linker namespace. No hook activated, no device test or APK.

### Gate 2L — Nine-binary provenance-closed graphics candidate (CI VERIFIED)

The separate closure workflow
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40590857186
completed **success** after correcting the NDK r27 path of
`libc++_shared.so` to
`toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android`.

The build re-downloads exact successful DXVK, Turnip+IMapper and
libadrenotools CI artifacts. It verifies the upstream source pins,
compares each binary SHA256 with its original builder report, checks
PE32+ AMD64 vs AArch64 ELF architecture, rejects ambiguous/missing
artifact files, and packs the matching NDK C++ runtime. The result is
**9 verified source-built components** and a manifest explicitly setting
`safe_to_release=false`; the ZIP is **not an APK** and is not installed.

The closure is static/source provenance only. Still unverified:
- signed APK-native loading (including Android 16 linker namespaces),
  true mapper/UBWC surface behavior, KGSL/Adreno 840 device creation;
- Wine/FEX child process progress, correct DXVK DLL override,
  Vulkan function loader handoff and Android X11 WSI presentation;
- at least two distinct guest-rendered frames shown on Android;
- compatibility and clean rollback when preserving user prefix/saves.

**Release gate stays OFF.** The existing signed v4.0.89 remains
untouched. Do not represent this candidate as a game fix.


### Gate 2M — Wine-process Vulkan bridge and inactive Android AAR (CI VERIFIED)

The next loader must be invoked **from the signed APK-native Wine child
process that requests libvulkan.so.1**, not from the Android Java activity
or its supervisor. The exact-source libadrenotools API
`adrenotools_open_libvulkan` uses flag
`ADRENOTOOLS_DRIVER_CUSTOM = 1`; the custom driver directory must end
in `/` because upstream concatenates the directory with the ICD filename.
The hook library directory must be the APK `nativeLibraryDir`.
Successful function return is NOT proof of custom ICD, Adreno enumeration,
an X11 swapchain, or Android Surface frames.

New code `tools/engine_vnext_wine_vulkan_bridge.{c,h}` exports an explicit
(no constructor, no system-wide dlopen() interception) function for a
future, manifest-verified Wine child. It demands the exact Linux Vulkan
SONAME `libvulkan.so.1`, the process's kernel-visible
`/proc/self/exe` match to the signed `libwineprobe.so`, and a caller
supplied verified-manifest gate. It rejects supervisor/wineserver and
arbitrary child processes, absent pinned native libraries, and unsafe
library roots. It requests the custom Turnip ICD through the
libadrenotools API without silently switching to the system driver if
opening fails. The C function **cannot** attest the Android APK signature
itself: a future signed Java/component manifest must validate and
authorize the call. A boolean parameter on its own is not security proof.
The bridge is NOT currently called by any Wine interposer.

Verified GitHub Actions:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40591736104
completed success for the strict -Werror/-pedantic host process policy
and pinned NDK/Bionic ARM64 bridge ELF ABI check. The original build
revealed a strict-ISO function-pointer cast issue, corrected through
POSIX dlsym + memcpy representation.

The Android source bridge AAR workflow
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40591979177
completed success. The actual Gradle Android library packaged this
**inactive** bridge ELF alongside the native Wine session supervisor
and verified both binaries' source SHA-256 bytes after AAR assembly.
The bridge has no live Wine hook or current Android on-device test.

### Gate 2N — Temporary full-source app APK packaging check (CI pending)

The full app source workflow now additionally compiles the inactive
Wine-child Vulkan bridge into the **temporary debug APK**, verifies that
APK's bridge ELF byte-for-byte against the NDK-built source output,
retains the original v4.0.89 Wine/FEX resources without changes, and
rejects any false claim that the engine is release-eligible. It then
deletes the APK; no new installable APK is published.
Workflow:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40592374006

This proves packaging only if that workflow completes successfully.
Critical unresolved integration:
1. Add a signed graphics provider manifest into the APK containing
   DXVK, Turnip, libadrenotools and libc++ SHA identities and their
   actual APK-native/PE install paths.
2. Ensure only the manifest-gated, supervised Wine **child** invokes
   the new loader bridge on the exact Wine Vulkan UnixLib dlopen path,
   with verified custom ICD selection and reliable cleanup/re-exec.
3. Validate Vulkan physical device and queue capabilities (including
   DXVK 2.7.1 requirements and real Android X11 WSI) on REDMAGIC 11 Pro.
4. Show >1 distinct game/Win32 D3D11 frames on the Android Surface,
   while preserving the prefix and signed APK upgrade identity.
No APK release or normal game activation before these proofs.


### Gate 2O — Signed-path graphics staging and Wine handoff integrity (SOURCE POLICY VERIFIED)

New source staging tool tools/stage_engine_graphics_apk.py strictly
verifies the nine files from the pinned DXVK/Turnip/AdrenoTools candidate
(run 40590857186), both the ZIP's manifest and the artifact sidecar,
all declared source pins, exact file list, PE/ELF ABI, and SHA-256.
It maps x64 Windows DXVK d3d11.dll / dxgi.dll into
assets/engine/providers/dxvk/x64/, and the seven AArch64
Turnip/AdrenoTools/NDK shared objects into lib/arm64-v8a/. Gradle
retains native ELF hashes and the APK static auditor checks all nine.
The official Mesa 26.2.0 archive uses a verified SHA-256 source pin
rather than an invented Git commit.

The Java-side EngineVNextGraphicsManifestGate can compare the
installed nativeLibraryDir's seven signed libraries and the two DXVK
APK assets with the APK-embedded graphics manifest. The future
EngineVNextWineHandoff invokes this integrity gate before launch
activation, and the pre-existing native manifest gate still rejects
activation outright. No Wine DLL override or Vulkan loader interception
has been enabled. User game files, Wine prefix and existing stable APK
are never modified by this source-only step.

The independent Python source policy workflow completed success:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40595660037
including rejection of missing/altered providers, inconsistent source
pins, fake GPU proof and APK hash mutation.

Full Java/Gradle compilation and ephemeral debug-APK packaging after
this integration are separate checks, not certified by the above
Python-only run:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/40595950816

Release is still OFF. Remaining physical proof: Wine child actually
calls the custom Vulkan loader, Android 16 linker namespace accepts
the Turnip/mapper dependency closure, the expected Adreno hardware is
enumerated, X11 Vulkan presents successfully, and multiple distinct
guest-rendered frames reach the real Android display. No APK is
published, and no CarX / external EXE compatibility is claimed.
