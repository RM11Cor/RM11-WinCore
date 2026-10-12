#include "RuntimeAdapterContract.h"
#include <cassert>
#include <cstring>
#include <dlfcn.h>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    assert(argc == 2);
    void* lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { std::cerr << dlerror() << "\n"; return 1; }
    auto info = reinterpret_cast<rm11_adapter_info_fn>(dlsym(lib, RM11_ADAPTER_INFO_SYMBOL));
    auto run = reinterpret_cast<rm11_adapter_test_fn>(dlsym(lib, RM11_ADAPTER_TEST_SYMBOL));
    assert(info && run);
    assert(info() == RM11_ADAPTER_ABI_VERSION);
    char output[256]{};
    assert(run(output, sizeof(output)) == 0);
    assert(std::strstr(output, "[PASS] RM11 native adapter invoked") != nullptr);
    assert(std::strstr(output, "not Wine or Box64") != nullptr);
    assert(run(nullptr, 0) == -1);
    char shortBuffer[8]{};
    assert(run(shortBuffer, sizeof(shortBuffer)) == -1);
    dlclose(lib);
    std::cout << "PASS: separate native .so, stable C ABI handshake, safe buffer checks\n";
}
