# FH5 Native Port — M19 APK proof-of-build

This isolated branch contains a **minimal ARM64 Vulkan capability diagnostic APK** to validate Android build infrastructure and GPU format support on a real device.

It is not FH5, not a port of ForzaTech, and does not include game files. No Steam account is required. It does not upload textures yet; that remains in the M18 source package and future integration.

**Isolation:** Git branch `fh5-native-port-m19-probe`, not merged to main or KERNIX. Intended to migrate to an independent FH5 repository.

Build: GitHub Actions → FH5 M19 Isolated ARM64 Vulkan Probe → download app-debug.apk from the run artifact. Requires Android 10+ ARM64.
