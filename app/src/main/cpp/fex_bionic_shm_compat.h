#pragma once
#include <sys/types.h>

// FEX-2609 uses shm_open/unlink for its optional per-process statistics.
// Bionic omits POSIX named-shm. Our implementation uses a same-process,
// kernel-backed memfd table, no external shared-memory path or world-write.
#ifdef __cplusplus
extern "C" {
#endif
int rm11_fex_shm_open(const char* name, int flags, mode_t mode);
int rm11_fex_shm_unlink(const char* name);
#ifdef __cplusplus
}
#endif
