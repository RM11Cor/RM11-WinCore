#pragma once
// RM11 internal native adapter ABI for Android ARM64 shared libraries.
// This is an integration contract, NOT a Box64 or Wine runtime ABI.
#include <stddef.h>
#include <stdint.h>

#define RM11_ADAPTER_ABI_VERSION 1u
#define RM11_ADAPTER_INFO_SYMBOL "rm11_adapter_info"
#define RM11_ADAPTER_TEST_SYMBOL "rm11_adapter_self_test"

#ifdef __cplusplus
extern "C" {
#endif
// Returns a stable ABI version; runtime adapters with a different version
// are rejected before their self-test is called.
typedef uint32_t (*rm11_adapter_info_fn)(void);
// Returns 0 on success; must NUL-terminate the output on successful return.
typedef int (*rm11_adapter_test_fn)(char *output, size_t capacity);
#ifdef __cplusplus
}
#endif
