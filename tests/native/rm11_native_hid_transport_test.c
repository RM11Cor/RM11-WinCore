#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../app/src/main/cpp/rm11_native_hid_transport.h"

typedef struct {
    int adds,reports,removes,fail_add,fail_report;
    uint16_t vendor,product;
    uint8_t last[RM11_HID_REPORT_BYTES];
} mock_pnp;
static int add(void *ctx,uint16_t v,uint16_t p,const uint8_t *d,size_t n){
    mock_pnp *m=(mock_pnp *)ctx;
    assert(d&&n>60&&d[0]==0x05&&d[1]==0x01);
    if(m->fail_add){m->fail_add=0;return -1;}
    m->adds++;m->vendor=v;m->product=p;
    return 0;
}
static int send(void *ctx,const uint8_t *b,size_t n){
    mock_pnp *m=(mock_pnp *)ctx;
    assert(n==RM11_HID_REPORT_BYTES);
    if(m->fail_report){m->fail_report=0;return -1;}
    m->reports++;memcpy(m->last,b,n);
    return 0;
}
static void remove_pad(void *ctx){
    mock_pnp *m=(mock_pnp *)ctx;m->removes++;
}
int main(void){
    rm11_shared_pad pad={0};
    pad.magic=RM11_HID_PAD_MAGIC;pad.version=RM11_HID_PAD_VERSION;
    pad.sequence=2;pad.connected=1;pad.buttons=0x1000;
    mock_pnp mock={0};
    rm11_hid_transport sink={&mock,add,send,remove_pad};
    rm11_hid_bus bus={0};

    mock.fail_add=1;
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==-1);
    assert(bus.registration_failures==1&&mock.adds==0);
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==1);
    assert(mock.adds==1&&mock.reports==1);
    assert(mock.vendor==RM11_HID_VENDOR_ID);
    assert(mock.product==RM11_HID_PRODUCT_ID);
    assert(mock.last[1]==1); /* Button A */
    assert(bus.published_reports==1);
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==0);
    assert(mock.reports==1); /* No duplicate reports. */

    pad.sequence=4;pad.buttons=0x2000;
    mock.fail_report=1;
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==-1);
    assert(bus.report_failures==1);
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==1);
    assert(mock.last[1]==2);
    assert(mock.reports==2);
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==0);

    pad.connected=0;pad.sequence=6;
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==0);
    assert(mock.removes==1);
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==0);
    assert(mock.removes==1);
    pad.connected=1;pad.sequence=8;pad.rt=255;
    assert(rm11_hid_bus_tick(&bus,&pad,&sink)==1);
    assert(mock.adds==2&&mock.reports==3);
    assert(mock.last[13]==255);
    rm11_hid_bus_stop(&bus,&sink);
    rm11_hid_bus_stop(&bus,&sink);
    assert(mock.removes==2);
    assert(rm11_hid_bus_tick(NULL,&pad,&sink)==-1);
    puts("RM11_NATIVE_WINEBUS_PNP_LIFECYCLE_RETRY_CONNECT_DISCONNECT_PASS");
    return 0;
}
