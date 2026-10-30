/*
 * RM11 native HID contract v1.
 *
 * Platform-independent bus payload, not a keyboard binding. A Wine-specific
 * adapter must publish this descriptor and input reports through its own
 * Unix/PnP bus; exporting a report alone does NOT enumerate any device.
 *
 * Android and the signed XInput DLL already share this EXACT 64-byte mapping.
 */
#ifndef RM11_NATIVE_HID_GAMEPAD_H
#define RM11_NATIVE_HID_GAMEPAD_H
#include <stddef.h>
#include <stdint.h>

#define RM11_HID_PAD_MAGIC UINT32_C(0x524d3131)
#define RM11_HID_PAD_VERSION UINT32_C(1)
#define RM11_HID_REPORT_ID 1
#define RM11_HID_REPORT_BYTES 14

typedef struct {
    uint32_t magic;                 /* 0 */
    uint32_t version;               /* 4 */
    volatile uint32_t sequence;     /* 8, even=committed */
    uint32_t connected;             /* 12 */
    uint16_t buttons;               /* 16, XInput mask */
    uint8_t lt, rt;                 /* 18, 19 */
    int16_t lx, ly, rx, ry;         /* 20..27 */
    uint32_t reserved;              /* 28 */
    volatile uint32_t getstate;     /* 32, Win64 XInput calls */
    volatile uint32_t capabilities; /* 36 */
    uint8_t padding[24];            /* 40..63 */
} rm11_shared_pad;

typedef struct {
    uint16_t buttons; /* XInput masks */
    int16_t lx, ly, rx, ry;
    uint8_t lt, rt;
    uint32_t connected;
    uint32_t sequence;
} rm11_hid_snapshot;

/* Returns 1 connected, 0 disconnected, -1 malformed/unstable state. */
int rm11_hid_read(const rm11_shared_pad *shared, rm11_hid_snapshot *snapshot);

/* Returns report byte count (14), 0 if pad absent, or -1 bad args. */
int rm11_hid_encode(const rm11_hid_snapshot *snapshot,
                    uint8_t *report, size_t capacity);

/* Stable HID 1.11 gamepad report descriptor (vendor-independent). */
const uint8_t *rm11_hid_descriptor(size_t *length);

#endif
