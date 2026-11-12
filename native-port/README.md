# CarX Street PC → genuine Android ARM64 native port route (no FEX/Wine)

## Engineering checkpoint — November 12, 2026

**This is an Android source-build route, NOT an executable CarX Street port.**

The user provided their original Windows PC extracted installation and
CarX_Street_PC_Port_Report_v0.9.json:

- 906 source files, 22,710,138,866 bytes. Unity source asset version
  indicated by both globalgamemanagers and resources.assets: 6000.3.8f1.
- GameAssembly.dll and UnityPlayer.dll are Windows PE/x86-64, not native
  Android ARM64 ELF shared libraries.
- 808 original Windows64 bundles; no proven Android-target compiled bundles.
- Original IL2CPP global metadata prefix is nonstandard; the first 4096
  bytes lack classic magic. No actual source code or Android game binary
  was recovered.
- Separate PortLab v0.6 native ARM64 Vulkan API/queue/offscreen pixel
  readback succeeded 1024/1024 on REDMAGIC NX809J. This is an
  independent demo, not an original CarX scene or gameplay frame.
- v0.9 physical/catalog filename reconciliation is partly inconclusive
  because one physical name and one catalog name are unsupported by
  the inspector's conservative normalizer. No missing game data proved.

**Do not generate more source inspector APKs. v0.9 is the retained tool.**

## Native Android route chosen

Unity documents that the IL2CPP backend converts managed game code to
C++ and compiles *platform-specific* native machine code, such as APK
for Android or DLL/EXE for Windows. The original Windows GameAssembly
DLL is NOT input to Unity's IL2CPP source compilation process.

Unity 6000.3 documentation:
https://docs.unity.com/en-us/engine/6000.3/manual/programming-environment/scripting-backends/il2cpp/il2cpp-introduction

Unity supports embedding a genuinely built Unity runtime in an
Android project via **Unity as a Library**:
https://docs.unity.com/en-us/engine/6000.3/manual/platform-specific/cross-platform-features/unityasa-library

Original Windows64 AssetBundles are NOT automatically Android-compatible:
https://docs.unity.com/en-us/engine/6000.3/manual/assets-and-media/assets-managing-runtime/assetbundles-section/asset-bundles-intro

### Phase A — acquire authorized real game Unity source and scenes (BLOCKED)

CarX developer/source owner must provide permission and legitimate
Unity project containing actual compatible C# gameplay code, Unity
scenes, prefabs, project package dependencies and original source assets.
A blank Unity project, PC GameAssembly.dll, catalog.json and Windows
AssetBundles do **not** qualify. Merely creating folders with .cs
files does not prove a real CarX game or permission.

The source project must be prepared under a local Unity root with
ProjectSettings/ProjectVersion.txt indicating 6000.3.8f1, and the
implementation-specific gameplay/scene integration paths:
    Assets/CarXStreetNativePort/Gameplay/*.cs
    Assets/CarXStreetNativePort/Scenes/*.unity

The sample paths are our own convention, not a claim about the
original developer's private source layout.

Do not upload/distribute proprietary CarX source or game binaries
to this public GitHub repository.

### Phase B — authorized Unity 6000.3.8f1 build to Android ARM64

On a machine with *Unity 6000.3.8f1 Editor* and Android Build Support
(including SDK, NDK and JDK), copy this original script:
    native-port/unity/CarXAuthorizedAndroidExport.cs

into the authorized project's:
    Assets/Editor/CarXAuthorizedAndroidExport.cs

Run:
    Tools -> CarX Native Port -> Export authorized Android ARM64 Gradle project

or, with Unity Editor installed and licensed:
    <UnityEditorExecutable> -batchmode -quit -projectPath <AuthorizedUnityRoot> \
       -executeMethod CarXAuthorizedAndroidExport.ExportAuthorizedProject \
       -logFile <UnityExportLogPath>

This script FAILS if source project version mismatch, no actual
C# files under our integration path, no real .unity scenes enabled
in Build Settings, or if the source project tries to include
StandaloneWindows64 bundles under Android StreamingAssets.

It configures:
    PlayerSettings.SetScriptingBackend(NamedBuildTarget.Android, IL2CPP)
    PlayerSettings.Android.targetArchitectures = ARM64
    Android graphics API = Vulkan
    EditorUserBuildSettings.exportAsGoogleAndroidProject = true

It exports a Gradle project with the native UnityLibrary runtime;
it does NOT publish or sign an APK or execute the original CarX PC
binary. UNITY EDITOR HAS NOT BEEN RUN BY OUR GITHUB CI; we cannot
claim the actual game's Unity project build passed.

A deliberately separate test package:
    com.rm11cor.carxstreet.nativecandidate

is used instead of replacing the user's working
com.rm11cor.carxstreet.portlab. Only after a real game scene and
controller proof may an intentional signed release strategy be
considered. Existing v0.9 permanent CarX APK signing identity
must not rotate or be overwritten with an unrelated Unity signing key.

### Phase C — verify native compiled Android artifact

After authorized Unity Gradle export/build of an APK, run:

    python3 native-port/tools/carx_native_android_artifact_gate.py \
       apk <result-native-android-candidate.apk> \
       --out <artifact-proof.json>

This gate requires:
- AndroidManifest.xml in the built package.
- Actual ELF64 little-endian AArch64 ET_DYN headers in:
  lib/arm64-v8a/libmain.so
  lib/arm64-v8a/libunity.so
  lib/arm64-v8a/libil2cpp.so
- Actual Unity runtime data under assets/bin/Data/.
- No Windows PC GameAssembly.dll / UnityPlayer.dll copied into
  the Android APK as fake game logic.
- Conservative ZIP bounds and invalid path prevention.

A header-only gate does NOT attest APK signature authenticity,
actual code origin, game rights, PC/Android content compatibility,
any executable CarX gameplay code, or a single real game frame.

The CLI also offers:
    python3 native-port/tools/carx_native_android_artifact_gate.py \
       project <authorized-unity-project-root>

for strict source project structure/version screening.

The CI tests (18 synthetic cases) are not an actual Unity Editor or
CarX game build.

### Phase D — real playable game proof (BLOCKED)

Required before claiming a successful native CarX Street PC port:

1. Authorized real PC-equivalent native Android game logic compiled
   and verified as executing on the user's ARM64 device.
2. Correct Android-target Addressables, shaders/textures and Unity
   resource dependencies built from allowed source assets.
3. Real game boot/scene and visible game-origin first frame.
4. Genuine vehicle physics, control mapping, save progress and input.
5. Legitimate online/game-service integrations when applicable.
   Do not bypass anti-cheat or authentication.

If actual game source and Android assets are unavailable, STOP at
Phase A. A hidden Wine/FEX translation runtime inside an APK would
be a different product, and violates the user's strict no-emulation
native-port requirement.

## Repository CI

.github/workflows/carx-real-unity-android-native-source-gate.yml

18 negative and positive *synthetic* tests for source-version,
source completeness, ELF architecture, Windows PE false positives,
missing Unity libraries, malformed APK paths and empty game content.
No original CarX files, confidential developer source or authentic
Android CarX build were used in these tests.
