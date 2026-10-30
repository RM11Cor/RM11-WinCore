#include "rm11_native_hid_gamepad.h"
#include <string.h>
#include <limits.h>

_Static_assert(sizeof(rm11_shared_pad)==64,"Android and Wine mmap ABI mismatch");
_Static_assert(offsetof(rm11_shared_pad,sequence)==8,"Wrong seqlock offset");
_Static_assert(offsetof(rm11_shared_pad,buttons)==16,"Wrong button offset");
_Static_assert(offsetof(rm11_shared_pad,lx)==20,"Wrong axis offset");
_Static_assert(offsetof(rm11_shared_pad,getstate)==32,"Wrong counter offset");

/* HID input layout:
 * ID (1B), 10 buttons + 6 padding bits (2B), hat (1B),
 * X/Y/Rx/Ry (4 x signed16), LT/RT (2 x unsigned8).
 * Total 14B including ID. 0x08 is a neutral/null hat.
 */
static const uint8_t descriptor[]={
    0x05,0x01,       /* Generic Desktop */
    0x09,0x05,       /* Game Pad */
    0xa1,0x01,       /* Application collection */
    0x85,RM11_HID_REPORT_ID,
    0x05,0x09,       /* Button page */
    0x19,0x01, 0x29,0x0a, /* buttons 1..10 */
    0x15,0x00, 0x25,0x01,
    0x75,0x01, 0x95,0x0a,
    0x81,0x02,       /* 10 button bits */
    0x75,0x06, 0x95,0x01,
    0x81,0x03,       /* 6 constant padding bits */
    0x05,0x01,
    0x09,0x39,       /* hat switch */
    0x15,0x00, 0x25,0x07,
    0x35,0x00, 0x46,0x3b,0x01, /* physical 315 degrees */
    0x65,0x14,       /* English rotation, degrees */
    0x75,0x04, 0x95,0x01,
    0x81,0x42,       /* data, variable, null allowed */
    0x75,0x04, 0x95,0x01,
    0x81,0x03,       /* 4 padding bits */
    0x65,0x00,       /* reset unit */
    0x09,0x30, 0x09,0x31, 0x09,0x33, 0x09,0x34,
    0x17,0x00,0x80,0xff,0xff, /* logical min -32768 */
    0x27,0xff,0x7f,0x00,0x00, /* logical max +32767 */
    0x75,0x10, 0x95,0x04,
    0x81,0x02,       /* axes 4 x signed16 */
    0x09,0x32, 0x09,0x35,     /* Z and Rz: analog triggers */
    0x15,0x00, 0x26,0xff,0x00, /* logical min 0, max 255 */
    0x75,0x08, 0x95,0x02,
    0x81,0x02,
    0xc0
};
const uint8_t *rm11_hid_descriptor(size_t *length){
    if(length)*length=sizeof(descriptor);
    return descriptor;
}
int rm11_hid_read(const rm11_shared_pad *shared,rm11_hid_snapshot *snapshot){
    if(!shared||!snapshot)return -1;
    for(int i=0;i<12;i++){
        uint32_t before=__atomic_load_n(&shared->sequence,__ATOMIC_ACQUIRE);
        if(before&1)continue;
        rm11_shared_pad local;
        memcpy(&local,shared,sizeof(local));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint32_t after=__atomic_load_n(&shared->sequence,__ATOMIC_ACQUIRE);
        if(before!=after || (after&1))continue;
        if(local.magic!=RM11_HID_PAD_MAGIC || local.version!=RM11_HID_PAD_VERSION)
            return -1;
        snapshot->sequence=after;
        snapshot->connected=local.connected?1u:0u;
        snapshot->buttons=local.buttons;
        snapshot->lx=local.lx;snapshot->ly=local.ly;
        snapshot->rx=local.rx;snapshot->ry=local.ry;
        snapshot->lt=local.lt;snapshot->rt=local.rt;
        return snapshot->connected?1:0;
    }
    return -1;
}
static void store16(uint8_t *dest,int16_t x) {
    uint16_t u=(uint16_t)x;
    dest[0]=(uint8_t)u;dest[1]=(uint8_t)(u>>8);
}
static uint8_t hat(uint16_t b){
    int up=(b&0x1)!=0,down=(b&0x2)!=0;
    int left=(b&0x4)!=0,right=(b&0x8)!=0;
    if(up==down)up=down=0;
    if(left==right)left=right=0;
    if(up)return right?1u:left?7u:0u;
    if(down)return right?3u:left?5u:4u;
    return right?2u:left?6u:8u;
}
int rm11_hid_encode(const rm11_hid_snapshot *s,uint8_t *out,size_t cap){
    if(!s||!out||cap<RM11_HID_REPORT_BYTES)return -1;
    if(!s->connected)return 0;
    memset(out,0,RM11_HID_REPORT_BYTES);
    out[0]=RM11_HID_REPORT_ID;
    static const uint16_t bits[]={
        0x1000,0x2000,0x4000,0x8000, /* A B X Y */
        0x0100,0x0200,             /* LB RB */
        0x0020,0x0010,             /* BACK START */
        0x0040,0x0080              /* L3 R3 */
    };
    uint16_t buttons=0;
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);i++)
        if(s->buttons&bits[i])buttons|=(uint16_t)(1u<<i);
    store16(out+1,(int16_t)buttons);
    out[3]=hat(s->buttons);
    /* XInput and SDL's Y axis use opposite coordinate orientations. */
    store16(out+4,s->lx);
    store16(out+6,(int16_t)(-((int32_t)s->ly)-1));
    store16(out+8,s->rx);
    store16(out+10,(int16_t)(-((int32_t)s->ry)-1));
    out[12]=s->lt;out[13]=s->rt;
    return RM11_HID_REPORT_BYTES;
}
