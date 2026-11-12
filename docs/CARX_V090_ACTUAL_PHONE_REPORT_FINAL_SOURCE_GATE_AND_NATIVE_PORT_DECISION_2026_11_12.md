# CarX Street PC — actual v0.9 device report and decision to stop inspector-only APKs

Date: 2026-11-12; phone REDMAGIC NX809J, Android 16, arm64-v8a.
User-provided file: CarX_Street_PC_Port_Report_v0.9.json.
Project: CarX native port branch carx-street-pc-port-v1.
Separate FH5 workflow remains separate; KERNIX is paused.

## v0.9 direct user-device source evidence

- Version 0.9.0, original Android SAF read-only source inspector.
- 906 original Windows game files, 21 folders, 22,710,138,866 bytes,
  scanning complete (375ms).
- GameAssembly.dll and UnityPlayer.dll remain Windows PE x86-64,
  bounded static import counts respectively 15 and 26. No original
  Windows executable was run.
- 808 original physical StandaloneWindows64 .bundle entries.
- Entire 54,490-ID Addressables catalog parsed (with 807 Windows64
  ID references and 807 generic .bundle extension refs).
- Accepted distinct physical .bundle basenames: 807. One unsupported
  physical basename rejected by *our conservative filename
  normalizer*, not by an Android filesystem read failure.
- Accepted distinct catalog bundle basenames: 806. One Windows64
  source reference rejected as an unsupported basename (NOT a nested
  path, per v0.9 category "unsupported_Windows64_bundle_basename").
- 806 accepted exact filename matches; the entire accepted catalog
  bundle name set is present among accepted original physical names.
- 1 accepted physical file is not referenced by accepted catalog
  names: player_layout.bundle.
- Zero accepted catalog-only names without a physical file.
- Both remaining unsupported basename examples were deliberately
  redacted by the strict safe output filter:
  [redacted_nonlocal_or_ambiguous_id]. They could refer to the same
  original filename or to different original filenames; **not
  determined by the report**. Do not guess.
- Report safely recorded an Android-named ID
  graphics_quality_android_view.json, but the Android-target path
  count was ZERO. This does NOT prove Android-compatible assets.
- The result is correctly marked fully_comparable=false,
  audit_status=both_physical_and_catalog_names_need_review.
  In contrast v0.8 incorrectly flagged the name rejection as
  bundle_count_or_input_limit_exceeded.
- NO hash-level asset integrity check was performed. Therefore a
  filename match is not proof the file bytes are complete or valid.
  But there is currently NO positively demonstrated missing game
  file and no justification to delete player_layout.bundle.

## Native Android GPU test still independently passed

Android ARM64 JNI independent Vulkan test on Adreno 840 (Vulkan
1.4.295) created a VkDevice, submitted a 32x32 RGBA8 GPU clear,
waited on the fence, copied the image and read back 1024/1024
correct pixels. This only validates our own GPU code. No CarX game
shader, visible game surface, game physics, player controls or
original scene has been run.

## FINAL engineering decision

CarX source asset/header/catalog **inventory phase is sufficiently
documented to stop cosmetic inspector-only APK updates**. No
more UI/reconciling releases solely to resolve the ambiguous
filename match unless a real game runtime/load test requires it.
Keep v0.9 as diagnostic reference. Never alter/delete game files.

The dominant unclosed prerequisites are:

G0 — Original playable CarX native Android ARM64/ELF+Bionic gameplay
code available from authorized re-build/source (or a distinct
independently written compatible game). NOT satisfied. The owner's
GameAssembly.dll is PE/x86-64 and cannot be compiled to Android
ARM64 by relabelling an APK or by JNI wrapping.

G1 — Platform-compatible Unity Android assets and matching scene
scripts/engine target, built with appropriate rights. NOT
satisfied. Unity's BuildAssetBundles API states bundles are
specific to their build target.

G2 — Actual original game scene load on Android and visible game
frame driven by gameplay, not an independent Vulkan synthetic
clear. NOT satisfied.

An APK packaging x86 translation and Windows API shims may be
a viable *game-specific preconfigured compatibility container*,
but it still uses emulation/translation/compatibility runtime and
is outside user's strict native-only goal.

Relevant Unity official documentation:
https://docs.unity3d.com/ja/6000.0/ScriptReference/BuildPipeline.BuildAssetBundles.html
https://docs.unity3d.com/ja/current/Manual/il2cpp-introduction.html

No original CarX proprietary binaries or bundles in GitHub CI.
The only file uploaded here was the small read-only v0.9 JSON
diagnostic report. No new playable APK is claimed or released.
