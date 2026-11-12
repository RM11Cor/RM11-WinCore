# CarX Street PC v0.7 original-game report -> v0.8 exact bundle name reconciliation

## Ground truth from the user-supplied v0.7 Android SAF report

- Original extracted CarX Street Windows PC installation: 906 files,
  21 folders, 22,710,138,866 total bytes, complete SAF traversal.
- GameAssembly.dll is Windows PE32+ x86-64 (142,049,792 bytes), with
  15 successfully parsed static import DLL names (including baselib.dll,
  kernel32.dll and WinRT libraries).
- UnityPlayer.dll is Windows PE32+ x86-64 (35,734,960 bytes), with
  26 static import names (including d3d11.dll, dxgi.dll, opengl32.dll).
  Steam/EAC not appearing in these two static import lists does NOT
  prove they are absent elsewhere in the PC launcher or dynamic imports.
- Unity Editor/source asset candidate 6000.3.8f1 from independent
  globalgamemanagers and resources.assets serialized-file headers.
- Original IL2CPP metadata first 4096 bytes have no classic magic;
  this is nonstandard, NOT proof of a known cipher or recoverable source.
- 808 actual .bundle files in StandaloneWindows64 with
  19,819,549,827 bytes total.
- Addressables catalog.json parsed completely: 54,490 internal IDs,
  807 IDs containing Windows64, 807 ending in bundle, only one
  ID containing the textual word Android.
- The one Android word reference does not prove Android-built bundles.
- Native Android C++ Vulkan work was previously device proven,
  1024/1024 correct offscreen GPU pixels on Adreno 840. No real
  CarX game logic or frame has executed.

Important: 808 actual files versus 807 catalog references does NOT
prove a missing asset. The v0.7 report omitted the full name lists.
A real per-filename audit is required to decide whether there is an
extra unreferenced file, a repeated catalog reference, a catalog-only
missing file, or merely different identification rules.

## Actual v0.8 implementation and independent verification

- BundleCatalogReconciler.java compares normalized physical filename
  set from the existing SAF scan with unique Windows64 bundle filenames
  extracted from the existing bounded catalog streaming parser.
- Distinguishes source-file count, unique physical filenames, unique
  referenced filenames, duplicates, physical-only files, catalog-only
  references, ambiguous paths, and text containing Android versus
  paths truly named for an Android content target.
- Never exports full proprietary bundle bytes, game DLLs or unbounded
  URLs/tokens; at most 12 sanitized basename examples per category.
- Fails closed if original physical listing incomplete, catalog parsing
  incomplete, or ambiguous filenames. It proves filename correspondence
  only; no hashes/content decoding or Unity runtime dependency closure.
- 22 standalone synthetic/corruption tests passed in original source
  GitHub Actions #43200816948. Native Android APK compile and stable
  certificate, application ID, versionCode 8, and AArch64 JNI library
  packaging checks also PASSED. No original CarX assets in GitHub CI.
- Separate independent SHA and signing validation/release workflow
  #43201264368 PASSED.
- APK v0.8 signed with original persistent CarX certificate:
  73759b890548a1cc52cc513ce859013e0e2c0884258f66ee19da45e59b30e2bc
  Package com.rm11cor.carxstreet.portlab, versionCode 8, allowing
  on-device in-place update over permanent-signed v0.7 versionCode7.

Actual release:
https://github.com/RM11Cor/RM11-WinCore/releases/tag/carx-street-portlab-v0.8.0-bundle-catalog-reconcile-20261112

Run the scanner on the user's same selected SAF folder; export
CarX_Street_PC_Port_Report_v0.8.json to identify the exact matching
result. Do not infer results before seeing the new device report.

## Native port fundamental blocker unchanged

PC GameAssembly.dll is PE/x86-64, not Android ELF/Bionic/AArch64.
Windows64 AssetBundles are platform-targeted. A genuine native Android
CarX Street PC game needs legally available target-specific game
logic/source plus appropriate Android-target Unity assets, or a clean
room game implementation. Bundled FEX/Wine would not count as the user's
strict no-emulation goal. Further inspector-only APKs should be avoided
unless tied to a concrete native game-code execution milestone.

Official Unity platform requirement:
https://docs.unity.com/en-us/engine/6000.0/manual/assets-and-media/assets-managing-runtime/assetbundles-section/platforms
