# RM11-WinCore v2.4.8 — Device Capability Probe / Runtime Preflight

## Added

* **DeviceCapabilityProbe**: actual Android-reported device model, ABI list, SoC if exposed, memory, available storage, Vulkan system feature (version and hardware level) and Android thermal status. No privileged permissions, root, or network.
* **RuntimeReadiness**: independently checks reported ARM64 ABI / Vulkan, and **verified-installed** runtime components. No component is considered installed without verification. The current APK always reports Wine/FEX/graphics runtime as not integrated.
* An optional **فحص الجهاز وVulkan وRAM** button displays the hardware readiness snapshot on device without rescanning or copying game files. The game scan JSON now includes `deviceReadiness` (schema 4).
* Existing detector, manifest, anti-cheat hints, and preflight remain unchanged. Test suite adds 6 tests for CPU ABI / Vulkan feature handling and readiness gating.

## Security and accuracy

* This APK is NOT a Windows game engine. It does not download or install Wine/Proton/FEX/Turnip or run EXE files. It is a prerequisite to choosing verified runtime components later.
* Advertised Vulkan feature does NOT guarantee Turnip/DXVK/VKD3D compatibility, Vulkan extensions, GPU performance, or Ray Tracing. Vendor requirements are not inferred from game binary names.
* 'available RAM' is a momentary Android report, not guaranteed continuous headroom.
* All data stays on device; no Internet access or location permissions.

## Upgrade

* applicationId unchanged: `com.rm11.autocore`.
* `versionCode 9` (previous v2.4.7 code 8).
* Same environment-driven stable release signing; never place the private PKCS12 key in a source ZIP.
* Existing `build-apk.yml` on GitHub should select the new ZIP with exact name `RM11-WinCore-v2.4.8-source.zip` and build a stable-signed APK.

## Testing

* Static source checks: `python3 scripts-check.py` from `RM11-WinCore` folder.
* Unit tests: Java/JUnit tests can run using Gradle. A local JUnit-compatible test harness also passed 44 tests. This is NOT equivalent to an APK installation test; confirm the GitHub Actions signed release before installing over the previous app.
* After installing press **فحص الجهاز وVulkan وRAM** and share a screenshot of that compact section. No need to upload huge game files or repeat CarX Street scans.
