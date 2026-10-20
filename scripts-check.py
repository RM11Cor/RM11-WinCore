#!/usr/bin/env python3
"""Reject structurally incomplete source ZIPs before the legacy build job runs."""
from pathlib import Path
needed = [
    'settings.gradle',
    'build.gradle',
    'app/build.gradle',
    'app/src/main/AndroidManifest.xml',
    'app/src/main/java/com/rm11/autocore/MainActivity.java',
    'app/src/main/java/com/rm11/autocore/GameDetector.java',
    'app/src/main/java/com/rm11/autocore/PeVersionReader.java',
    'app/src/main/java/com/rm11/autocore/PeImportReader.java',
    'app/src/main/java/com/rm11/autocore/GameManifestReader.java',
    'app/src/main/java/com/rm11/autocore/CompatibilityPlanner.java',
    'app/src/main/java/com/rm11/autocore/RuntimeReadiness.java',
    'app/src/main/java/com/rm11/autocore/DeviceCapabilityProbe.java',
    'app/src/test/java/com/rm11/autocore/RuntimeReadinessTest.java',
    'app/src/test/java/com/rm11/autocore/GameDetectorTest.java',
    'app/src/test/java/com/rm11/autocore/GameManifestReaderTest.java',
    'app/src/test/java/com/rm11/autocore/PeImportReaderTest.java',
    'app/src/test/java/com/rm11/autocore/CompatibilityPlannerTest.java'
]
for filename in needed:
    path = Path(filename)
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit('MISSING OR EMPTY: ' + filename)
needed.extend([
    'app/src/main/cpp/CMakeLists.txt',
    'app/src/main/cpp/vulkan_probe.c',
    'app/src/main/java/com/rm11/autocore/VulkanNativeProbe.java',
    'app/src/main/java/com/rm11/autocore/VulkanEvidence.java',
    'app/src/test/java/com/rm11/autocore/VulkanEvidenceTest.java',
])
for filename in needed:
    path = Path(filename)
    if not path.is_file() or path.stat().st_size == 0:
        raise SystemExit('MISSING OR EMPTY: ' + filename)
print('RM11 AutoCore v2.4.12: structure OK (not an APK runtime test).')

# Protect upgrade identity and signed-release configuration.
config = Path('app/build.gradle').read_text(encoding='utf-8')
checks = {
    "stable applicationId": "applicationId 'com.rm11.autocore'",
    'monotonic versionCode': 'versionCode 13',
    'release versionName': "versionName '2.4.12-alpha'",
    'stable release signing': 'signingConfig signingConfigs.stable',
    'keystore from environment': "System.getenv('RM11_RELEASE_KEYSTORE')",
    'password from environment': "System.getenv('RM11_RELEASE_PASSWORD')",
    'native ARM64 only': "abiFilters 'arm64-v8a'",
    'NDK pinned': "ndkVersion '27.2.12479018'",
    'CMake native source': "src/main/cpp/CMakeLists.txt",
}
for label, value in checks.items():
    if value not in config:
        raise SystemExit('INVALID BUILD CONFIG (' + label + '): ' + value)
print('RM11 v2.4.12: update identity and signing configuration OK')

# Regression guard for GitHub Actions run #79:
# Android Gradle Plugin permits abiFilters under defaultConfig.ndk,
# whereas android.ndk {...} fails evaluation before native compilation.
import re
if not re.search(r"defaultConfig\s*\{[^{}]*ndk\s*\{[^{}]*abiFilters\s+['\"]arm64-v8a['\"][^{}]*\}[^{}]*\}", config, re.S):
    raise SystemExit('INVALID BUILD CONFIG: abiFilters must be inside defaultConfig { ndk { ... } }')
if re.search(r"(?m)^\s*ndk\s*\{", config) and not re.search(r"defaultConfig\s*\{[^{}]*ndk\s*\{", config, re.S):
    raise SystemExit('INVALID BUILD CONFIG: root android.ndk block is not supported')
print('RM11 v2.4.12: NDK DSL placement regression check OK')


# Vulkan Swapchain/Surface presentation test must be in tracked source.
for source_file in [
    'app/src/main/cpp/vulkan_render.c',
    'app/src/main/java/com/rm11/autocore/VulkanRenderActivity.java',
    'app/src/main/java/com/rm11/autocore/VulkanFrameRenderer.java',
]:
    if not Path(source_file).is_file():
        raise SystemExit('MISSING RENDERER SOURCE: ' + source_file)
if 'rm11_vulkan_render' not in Path('app/src/main/cpp/CMakeLists.txt').read_text(encoding='utf-8'):
    raise SystemExit('MISSING RENDER LIBRARY IN CMAKE')
print('RM11 v2.4.12: Vulkan renderer source structure OK.')


# v2.4.12 five-stage shader/graphics/compute/timing/readiness regression checks
files = [
    'shaders/triangle.vert', 'shaders/triangle.frag', 'shaders/check.comp',
    'tools/compile_shaders.py', 'app/src/main/cpp/vulkan_suite.c',
    'app/src/main/cpp/rm11_shaders_generated.h',
    'app/src/main/java/com/rm11/autocore/VulkanSuite.java',
    'app/src/main/java/com/rm11/autocore/VulkanSuiteActivity.java',
]
for source in files:
    if not Path(source).is_file() or not Path(source).stat().st_size:
        raise SystemExit('Missing five-stage source: ' + source)
native = Path('app/src/main/cpp/vulkan_suite.c').read_text(encoding='utf-8')
for token in ['vkCreateGraphicsPipelines','vkCmdDraw','vkCreateComputePipelines','vkCmdDispatch',
              'vkCmdWriteTimestamp','vkGetQueryPoolResults','vkQueuePresentKHR']:
    if token not in native: raise SystemExit('Missing Vulkan operation: ' + token)
print('RM11 v2.4.12 five-stage shader/compute/presentation source checks OK.')
