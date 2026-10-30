/* Wine makedep: this source must NEVER be compiled as a Windows PE object.
 * Matching upstream Winebus unixlib.c and bus_sdl.c declarations. */
#if 0
#pragma makedep unix
#endif

#include "rm11_native_hid_transport.h"
#include <string.h>

int rm11_hid_bus_tick(rm11_hid_bus *bus,const rm11_shared_pad *pad,
                      const rm11_hid_transport *sink){
    if(!bus||!pad||!sink||!sink->register_gamepad||
            !sink->send_report||!sink->remove_gamepad)return -1;
    rm11_hid_snapshot snapshot={0};
    int status=rm11_hid_read(pad,&snapshot);
    if(status<0)return -1;
    if(status==0){
        if(bus->present){
            sink->remove_gamepad(sink->context);
            bus->present=0;
        }
        bus->valid_snapshot=0;
        return 0;
    }
    if(!bus->present){
        size_t descriptor_len=0;
        const uint8_t *descriptor=rm11_hid_descriptor(&descriptor_len);
        if(sink->register_gamepad(sink->context,RM11_HID_VENDOR_ID,
                                 RM11_HID_PRODUCT_ID,
                                 descriptor,descriptor_len)){
            bus->registration_failures++;
            return -1;
        }
        bus->present=1;
        bus->valid_snapshot=0;
    }
    if(bus->valid_snapshot&&snapshot.sequence==bus->last_sequence)return 0;
    uint8_t report[RM11_HID_REPORT_BYTES];
    if(rm11_hid_encode(&snapshot,report,sizeof(report))!=RM11_HID_REPORT_BYTES)
        return -1;
    if(sink->send_report(sink->context,report,sizeof(report))){
        bus->report_failures++;
        return -1; /* Retry same sequence on next tick. */
    }
    bus->valid_snapshot=1;
    bus->last_sequence=snapshot.sequence;
    bus->published_reports++;
    return 1;
}

void rm11_hid_bus_stop(rm11_hid_bus *bus,const rm11_hid_transport *sink){
    if(!bus||!sink)return;
    if(bus->present&&sink->remove_gamepad)
        sink->remove_gamepad(sink->context);
    bus->present=0;
    bus->valid_snapshot=0;
}
