/*
 * KERNIX independent Android ARM64 host bridge, API v1.
 * Copyright (c) 2026 KERNIX contributors. SPDX-License-Identifier: MIT
 *
 * This library provides host capability discovery only. It does NOT provide
 * x86 translation, Wine, Vulkan graphics presentation or game launching.
 * No Bannerlator/Winlator source is used.
 */
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>

#if !defined(__ANDROID__) || !defined(__aarch64__)
#error KERNIX host v1 requires Android AArch64
#endif

#if defined(__GNUC__)
#define KERNIX_EXPORT __attribute__((visibility("default")))
#else
#define KERNIX_EXPORT
#endif

enum {
    KERNIX_HOST_ABI_VERSION = 1u,
    KERNIX_CAP_ANDROID_ARM64 = 1u << 0,
    KERNIX_CAP_VULKAN_LOADER = 1u << 1,
    KERNIX_CAP_VULKAN_INSTANCE_VERSION_QUERY = 1u << 2,
    KERNIX_CAP_VULKAN_API_1_1_OR_NEWER = 1u << 3
};

struct kernix_host_info_v1 {
    uint32_t struct_size;
    uint32_t api_version;
    uint32_t capabilities;
    uint32_t vulkan_instance_api_version;
};

typedef int32_t (*kernix_vk_enumerate_instance_version)(uint32_t *);
typedef void *(*kernix_dl_open)(const char *, int);
typedef void *(*kernix_dl_symbol)(void *, const char *);
typedef int (*kernix_dl_close)(void *);

struct kernix_loader_v1 {
    kernix_dl_open open;
    kernix_dl_symbol symbol;
    kernix_dl_close close;
};

static uint32_t kernix_probe(struct kernix_host_info_v1 *out,
                             const struct kernix_loader_v1 *loader) {
    if (!out || !loader || !loader->open || !loader->symbol || !loader->close) {
        return 0u;
    }
    if (out->struct_size < sizeof(*out)) {
        return 0u;
    }
    out->api_version = KERNIX_HOST_ABI_VERSION;
    out->capabilities = KERNIX_CAP_ANDROID_ARM64;
    out->vulkan_instance_api_version = 0u;

    void *vk = loader->open("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!vk) {
        return out->capabilities;
    }
    out->capabilities |= KERNIX_CAP_VULKAN_LOADER;

    void *symbol = loader->symbol(vk, "vkEnumerateInstanceVersion");
    if (symbol) {
        /* memcpy avoids ISO C's undefined direct function-pointer cast. */
        kernix_vk_enumerate_instance_version enumerate = NULL;
        __builtin_memcpy(&enumerate, &symbol, sizeof(enumerate));
        uint32_t version = 0;
        if (enumerate && enumerate(&version) == 0) {
            out->vulkan_instance_api_version = version;
            out->capabilities |= KERNIX_CAP_VULKAN_INSTANCE_VERSION_QUERY;
            /* VK_API_VERSION_MAJOR 7-bit, MINOR 10-bit */
            uint32_t major = version >> 22;
            uint32_t minor = (version >> 12) & 0x3ffu;
            if (major > 1u || (major == 1u && minor >= 1u)) {
                out->capabilities |= KERNIX_CAP_VULKAN_API_1_1_OR_NEWER;
            }
        }
    }
    loader->close(vk);
    return out->capabilities;
}

KERNIX_EXPORT uint32_t kernix_host_abi_version(void) {
    return KERNIX_HOST_ABI_VERSION;
}

KERNIX_EXPORT uint32_t kernix_host_probe_v1(struct kernix_host_info_v1 *out) {
    const struct kernix_loader_v1 loader = {dlopen, dlsym, dlclose};
    return kernix_probe(out, &loader);
}
