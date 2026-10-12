#include <jni.h>
#include "RuntimeAdapterContract.h"
#include <dlfcn.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sstream>
#include <string>

// This is a REAL native library smoke test executed inside RM11's own process.
// It deliberately never loads third-party ELF, Wine, Box64, or a Windows executable.
extern "C" JNIEXPORT jstring JNICALL
Java_com_rm11_wincore_NativeRuntimeBridge_nativeSelfTest(JNIEnv* env, jclass) {
    std::ostringstream out;
    out << "RM11 WinCore 0.7-A / Packaged Native Runtime Smoke Test\n";
    out << "Executing JNI C++ code from RM11's own APK; NOT Windows emulation.\n\n";
#if defined(__aarch64__)
    out << "[PASS] Compiled native architecture: ARM64 (aarch64)\n";
#else
    out << "[FAIL] Compiled native architecture is NOT ARM64\n";
#endif
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize > 0) out << "[PASS] Host page size: " << pageSize << " bytes\n";
    else out << "[FAIL] Cannot determine host page size\n";

    struct utsname kernel{};
    if (uname(&kernel) == 0) {
        out << "[PASS] Linux kernel machine: " << kernel.machine << "\n";
    } else {
        out << "[FAIL] uname() failed\n";
    }

    // Check that the Android Bionic linker can load a host library within this process.
    // This is NOT a glibc, Box64, or Wine test.
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    if (!libc) {
        out << "[FAIL] Bionic libc.so dlopen failed\n";
    } else {
        void* sym = dlsym(libc, "getpid");
        out << (sym ? "[PASS] Android linker resolved libc.so:getpid\n"
                    : "[FAIL] Android linker could not resolve getpid\n");
        dlclose(libc);
    }
    out << "Host process ID (PID): " << static_cast<long>(getpid()) << "\n";
    out << "\n[NOT INTEGRATED] Wine, Box64, glibc rootfs, DXVK and EXE launching are absent.\n";
    out << "[NEXT] Obtain license-compliant ARM64 runtime builds and integrate via Android-compatible packaging.\n";
    return env->NewStringUTF(out.str().c_str());
}


// V0.8: dynamically load a SECOND shared library packaged inside the same
// APK and call a versioned C ABI entrypoint. We NEVER load user-supplied ELF.
extern "C" JNIEXPORT jstring JNICALL
Java_com_rm11_wincore_NativeRuntimeBridge_nativeAdapterTest(JNIEnv* env, jclass) {
    std::ostringstream out;
    out << "RM11 WinCore 0.8 / Packaged ARM64 Adapter Contract\n";
    out << "Android in-APK native module only; no Windows program launched.\n\n";
    void* module = dlopen("librm11runtime_adapter.so", RTLD_NOW | RTLD_LOCAL);
    if (!module) {
        const char* linkerError = dlerror();
        out << "[FAIL] dlopen packaged adapter: "
            << (linkerError ? linkerError : "unknown linker error") << "\n";
        return env->NewStringUTF(out.str().c_str());
    }
    dlerror();
    auto info = reinterpret_cast<rm11_adapter_info_fn>(dlsym(module, RM11_ADAPTER_INFO_SYMBOL));
    auto test = reinterpret_cast<rm11_adapter_test_fn>(dlsym(module, RM11_ADAPTER_TEST_SYMBOL));
    if (!info || !test) {
        out << "[FAIL] Adapter required ABI symbols missing\n";
    } else if (info() != RM11_ADAPTER_ABI_VERSION) {
        out << "[FAIL] Adapter ABI version mismatch\n";
    } else {
        out << "[PASS] Adapter ABI version: " << RM11_ADAPTER_ABI_VERSION << "\n";
        char buffer[256]{};
        if (test(buffer, sizeof(buffer)) == 0) {
            out << buffer << "\n";
            out << "[PASS] dlopen + dlsym + cross-library native call\n";
        } else {
            out << "[FAIL] Adapter self-test returned failure\n";
        }
    }
    dlclose(module);
    out << "\n[NOT INTEGRATED] Box64, Wine, glibc rootfs, EXE launch and DXVK.\n";
    out << "[NEXT] Build + audit licensed Android-compatible runtime components.\n";
    return env->NewStringUTF(out.str().c_str());
}
