#include "RuntimeAdapterContract.h"
#include <cstdio>
#include <cstring>

// Independent .so built and packaged by RM11's Android NDK build.
// This verifies C ABI cross-library calls; it is intentionally not Box64/Wine.
extern "C" __attribute__((visibility("default"))) uint32_t rm11_adapter_info(void) {
    return RM11_ADAPTER_ABI_VERSION;
}

extern "C" __attribute__((visibility("default"))) int
rm11_adapter_self_test(char *output, size_t capacity) {
    if (!output || capacity < 64) return -1;
#if defined(__aarch64__)
    constexpr const char *arch = "aarch64";
#else
    constexpr const char *arch = "non-ARM64 TEST HOST";
#endif
    int result = std::snprintf(output, capacity,
        "[PASS] RM11 native adapter invoked via C ABI. Architecture: %s. "
        "Adapter is not Wine or Box64.", arch);
    return (result >= 0 && static_cast<size_t>(result) < capacity) ? 0 : -2;
}
