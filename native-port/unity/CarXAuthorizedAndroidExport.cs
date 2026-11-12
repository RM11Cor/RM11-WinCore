// Place in Assets/Editor/CarXAuthorizedAndroidExport.cs of an AUTHORIZED
// Unity 6000.3.8f1 source project (not in the extracted Windows game folder).
// No original CarX game code or assets are included here.
//
// This does not reconstruct game code from GameAssembly.dll. The user/developer
// must supply actual rights-cleared gameplay SOURCE and Android-ready assets.
#if UNITY_EDITOR
using System;
using System.IO;
using System.Linq;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;
using UnityEngine.Rendering;

public static class CarXAuthorizedAndroidExport
{
    private const string ExpectedUnity = "6000.3.8f1";
    private const string GameplayRoot = "Assets/CarXStreetNativePort/Gameplay";
    private const string SceneRoot = "Assets/CarXStreetNativePort/Scenes/";
    private const string Output = "Builds/CarXNativeAndroid/ExportedGradle";
    private const string CandidatePackage = "com.rm11cor.carxstreet.nativecandidate";

    [MenuItem("Tools/CarX Native Port/Export authorized Android ARM64 Gradle project")]
    public static void ExportAuthorizedProject()
    {
        // An empty Unity project or extracted StandaloneWindows64 game folder
        // is NOT enough to meet this project-specific gameplay-source gate.
        if (Application.unityVersion != ExpectedUnity)
            throw new InvalidOperationException(
                "Wrong Unity Editor version. Expected " + ExpectedUnity +
                ", got " + Application.unityVersion);

        if (!Directory.Exists(GameplayRoot))
            throw new InvalidOperationException(
                "NO_AUTHORIZED_GAMEPLAY_SOURCE: missing " + GameplayRoot);

        var gameplayScripts = Directory.GetFiles(
            GameplayRoot, "*.cs", SearchOption.AllDirectories);
        if (gameplayScripts.Length == 0)
            throw new InvalidOperationException(
                "NO_AUTHORIZED_GAMEPLAY_SOURCE: original game C# source not supplied");

        var scenes = EditorBuildSettings.scenes
            .Where(scene => scene.enabled)
            .Select(scene => scene.path.Replace('\\', '/'))
            .Where(path => path.StartsWith(SceneRoot, StringComparison.Ordinal))
            .Where(File.Exists)
            .ToArray();
        if (scenes.Length == 0)
            throw new InvalidOperationException(
                "NO_NATIVE_GAME_SCENE: add real owner-authorized CarX game scenes " +
                "under " + SceneRoot + " and enable them in Build Settings");

        // Detect a common false step: renaming/copying PC Addressables into
        // an Android export. Android-compatible bundles must be rebuilt
        // from original Unity project assets for BuildTarget.Android.
        var pcStreaming = "Assets/StreamingAssets/aa/StandaloneWindows64";
        if (Directory.Exists(pcStreaming))
            throw new InvalidOperationException(
                "PC_WINDOWS64_BUNDLES_PRESENT: remove desktop-target bundles " +
                "from candidate Android project's StreamingAssets; this script " +
                "does NOT convert or delete any original files");

        if (Directory.Exists(Output))
            throw new InvalidOperationException(
                "OUTPUT_EXISTS: export path already exists. Back it up or select " +
                "a clean output folder manually. The tool will not delete it");

        // This is a candidate package ID, NOT the existing permanently-signed
        // PortLab inspector application. No APK is published or signed here.
        PlayerSettings.SetApplicationIdentifier(
            NamedBuildTarget.Android, CandidatePackage);
        PlayerSettings.SetScriptingBackend(
            NamedBuildTarget.Android, ScriptingImplementation.IL2CPP);
        PlayerSettings.Android.targetArchitectures = AndroidArchitecture.ARM64;
        PlayerSettings.SetGraphicsAPIs(
            BuildTarget.Android, new[] { GraphicsDeviceType.Vulkan });

        if (EditorUserBuildSettings.activeBuildTarget != BuildTarget.Android &&
            !EditorUserBuildSettings.SwitchActiveBuildTarget(
                BuildTargetGroup.Android, BuildTarget.Android))
            throw new InvalidOperationException(
                "ANDROID_TARGET_UNAVAILABLE: install Unity Android Build Support, SDK, NDK and JDK");

        Directory.CreateDirectory("Builds/CarXNativeAndroid");
        EditorUserBuildSettings.exportAsGoogleAndroidProject = true;

        var options = new BuildPlayerOptions {
            scenes = scenes,
            locationPathName = Output,
            target = BuildTarget.Android,
            targetGroup = BuildTargetGroup.Android,
            options = BuildOptions.None
        };
        var report = BuildPipeline.BuildPlayer(options);
        if (report == null || report.summary.result != BuildResult.Succeeded)
            throw new InvalidOperationException(
                "ANDROID_UNITY_IL2CPP_EXPORT_FAILED: consult Unity BuildReport");
        if (!Directory.Exists(Path.Combine(Output, "unityLibrary")))
            throw new InvalidOperationException(
                "UNITY_ANDROID_EXPORT_MISSING_LIBRARY: no unityLibrary module");

        Debug.Log(
            "CARX_NATIVE_CANDIDATE_UNITY_ANDROID_GRADLE_EXPORTED " + Output +
            " ARM64 IL2CPP Vulkan scenes=" + scenes.Length +
            ". This is NOT proof original CarX game runs. Validate game source " +
            "and scene provenance, Android platform assets, native Gradle ELF " +
            "artifacts and first real game frame before calling it a port.");
    }

    // Batch mode: -executeMethod CarXAuthorizedAndroidExport.ExportAuthorizedProject
}
#endif
