#ifndef RM11_NATIVE_HID_TRANSPORT_H
#define RM11_NATIVE_HID_TRANSPORT_H
#include "rm11_native_hid_gamepad.h"

#define RM11_HID_VENDOR_ID 0x3f0b
#define RM11_HID_PRODUCT_ID 0x4905

/*
 * Abstract PnP device interface. The final Wine adapter must implement
 * register/remove through the *matched* winebus.sys Unix ABI, not by sending
 * keyboard events or by calling arbitrary unverified Wine exports.
 *
 * register_gamepad returns 0 on success; includes actual HID descriptor.
 * send_report returns 0 on success; report contains report ID at byte zero.
 * remove_gamepad is called exactly once per previously registered device.
 */
typedef struct {
    void *context;
    int (*register_gamepad)(void *context, uint16_t vendor, uint16_t product,
                            const uint8_t *descriptor, size_t descriptor_len);
    int (*send_report)(void *context,const uint8_t *report,size_t len);
    void (*remove_gamepad)(void *context);
} rm11_hid_transport;

typedef struct {
    uint32_t last_sequence;
    int present;
    int valid_snapshot;
    uint64_t published_reports;
    uint64_t registration_failures;
    uint64_t report_failures;
} rm11_hid_bus;

/*
 * Call from Winebus's existing event dispatch worker at most once per
 * shared-state update. No threads, JNI, SDL or blocking I/O in this core.
 *  1 report published; 0 unchanged or device removed;
 * -1 unstable mmap, invalid callback or failed transport publication.
 */
int rm11_hid_bus_tick(rm11_hid_bus *bus,
                      const rm11_shared_pad *pad,
                      const rm11_hid_transport *transport);

/* Cleanly remove an existing Wine PnP device at session shutdown. */
void rm11_hid_bus_stop(rm11_hid_bus *bus,
                       const rm11_hid_transport *transport);

#endif
