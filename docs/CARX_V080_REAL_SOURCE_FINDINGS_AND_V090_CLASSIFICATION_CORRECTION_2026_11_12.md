# CarX Street PC: v0.8 user device source result and v0.9 classification fix

Date 2026-11-12. CarX branch carx-street-pc-port-v1. KERNIX paused, FH5 separate.

## Exact findings from owner-provided v0.8 real device JSON

- Original game user-selected SAF folder: 906 files, 21 folders, 22,710,138,866 bytes, complete scan.
- GameAssembly.dll Windows PE/x86-64, 15 parsed static DLL imports.
- UnityPlayer.dll Windows PE/x86-64, 26 parsed static DLL imports.
- Unity SerializedFile header 6000.3.8f1 in two independent original source files.
- Native C++ Android ARM64 Vulkan GPU clear+readback previously succeeded with 1024/1024 verified RGBA pixels. THIS IS NOT original CarX game execution or a frame.
- Original 808 physical Windows64 .bundle files (19,819,549,827 bytes).
- Fully parsed Unity Addressables 54,490 m_InternalIds; of these, 807 Windows64 bundle reference entries.
- 807 accepted distinct physical basenames; 0 duplicate accepted physical names.
- 806 accepted distinct catalog Windows64 bundle basenames; 0 duplicate accepted catalog names; 1 ambiguous Windows64 catalog reference.
- Exactly 806 accepted basename matches.
- Exactly ONE accepted physical filename not found among accepted catalog basenames: player_layout.bundle.
- ZERO accepted catalog basenames are missing among accepted physical files.
- One catalog ID contains Android wording: graphics_quality_android_view.json. ZERO actual Android target path references detected in the ID strings. Android word != Android compiled game bundles.

Important: original v0.8 report says fully_comparable=false, status=bundle_count_or_input_limit_exceeded.

## Proven v0.8 inspector software classification bug

The physical reconciliation input had 808 files, but accepted distinct physical names=807 and duplicate count=0. This implies ONE physically present basename was rejected by original normalization. In v0.8 the implementation uses the SAME limitHit flag for basename rejection and actual maximum distinct-name overflow. With only 808 sources versus MAX_BUNDLES 12,000, source count overflow is NOT the cause. The rejected actual basename was NOT included in v0.8 JSON; it cannot be recovered by guessing from that report.

Separately exactly ONE Windows64 catalog reference was ambiguous: nested-path versus unsupported filename is NOT determined by v0.8. It may or may not refer to the otherwise unlisted physical player_layout.bundle. The exact relationship is unproven. Do not delete any game file.

## Corrected source classification in v0.9

- Dedicated unsupportedPhysicalBasenameCount and safe redacted samples.
- Dedicated ambiguousCatalogNameExamples classified as nested Windows64 path versus unsupported basename.
- If both categories occur, honest status is both_physical_and_catalog_names_need_review.
- Original no-copy SAF reader, Unity source probes, native ARM64 Vulkan bootstrap and same permanent CarX signer are preserved.
- Android app ID com.rm11cor.carxstreet.portlab and monotonic versionCode 9 permit normal in-place update over the permanent-signed v0.8 versionCode 8.
- Corrected output is still a filename-level read-only audit, NOT game-engine or native gameplay proof.

## Native port gating

Fundamental blocker stays open: original GameAssembly.dll is Windows PE/x86-64, not Android ELF/Bionic/AArch64 native code; Windows64 Unity bundles are not proven Android compatible. A true Android port of CarX Street PC requires authorized native Android game logic/source and Android-target game assets or an independently implemented alternative game. A self-contained Wine/FEX wrapper remains compatibility runtime, NOT a strict native no-emulation port.

No more cosmetic diagnostic-only version increments should be undertaken after classification without a direct original game execution route.
