# RM11-WinCore v2.4.10 — Fix Android Gradle Plugin NDK DSL

## Actual failure
GitHub Actions build #79 failed **before compiling JNI** at app/build.gradle:8: `Could not find method ndk()` on Android extension. It is not a Vulkan runtime or signing issue.

## Change
Moved `ndk { abiFilters 'arm64-v8a' }` into `android.defaultConfig`, preserving pinned NDK version at android level and the existing CMake source and stable signing setup. Added regression validation in `scripts-check.py`. Incremented `versionCode` from 10 to 11 and renamed version to `2.4.10-alpha`.

## Verification boundary
Source structure checks, Java unit tests, and C syntax preflight are performed locally. Real Android Gradle/CMake/NDK APK build and test on phone **must be verified** in GitHub Actions and on the device. Vulkan probe still does not run Windows EXE.

Repo: https://github.com/RM11Cor/RM11-WinCore
