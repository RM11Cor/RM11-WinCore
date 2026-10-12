plugins {
    id("com.android.application")
}

android {
    namespace = "com.rm11.wincore"
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.rm11.wincore.test"
        minSdk = 30
        targetSdk = 35
        versionCode = 42
        versionName = "2.3.8"
        externalNativeBuild {
            cmake { cppFlags += "-std=c++17" }
        }
        ndk { abiFilters += "arm64-v8a" }
    }

    // Stable PROTOTYPE debug signature shared across CI runs.  This test-only key is
    // intentionally distributed with this source ZIP and MUST NOT sign production APKs.
    // A secure published release must instead use a protected production keystore.
    signingConfigs {
        create("rm11PrototypeDebug") {
            storeFile = file("../signing/rm11-development.jks")
            storePassword = "android"
            keyAlias = "rm11-dev"
            keyPassword = "android"
        }
    }

    // Extract native ELF entries to nativeLibraryDir; Android 10+ rejects exec from writable app files.
    packaging {
        jniLibs { useLegacyPackaging = true }
    }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("rm11PrototypeDebug")
        }
        // Release intentionally remains unsigned until a separately protected
        // publishing key is configured.  Never release with the prototype key.
        release { isMinifyEnabled = false }
    }
}
