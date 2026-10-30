#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../app/src/main/cpp/rm11_native_hid_gamepad.h"

static rm11_shared_pad connected(void){
    rm11_shared_pad p={0};
    p.magic=RM11_HID_PAD_MAGIC;p.version=RM11_HID_PAD_VERSION;
    p.connected=1;p.sequence=2;
    return p;
}
static void sample(const rm11_shared_pad *p,uint8_t out[RM11_HID_REPORT_BYTES]){
    rm11_hid_snapshot s={0};
    assert(rm11_hid_read(p,&s)==1);
    assert(rm11_hid_encode(&s,out,RM11_HID_REPORT_BYTES)==RM11_HID_REPORT_BYTES);
    assert(out[0]==RM11_HID_REPORT_ID);
}
int main(void){
    rm11_shared_pad p=connected();
    rm11_hid_snapshot s={0};
    uint8_t report[RM11_HID_REPORT_BYTES]={0};
    size_t desc_len=0;
    const uint8_t *desc=rm11_hid_descriptor(&desc_len);
    assert(desc!=NULL && desc_len>60 && desc[0]==0x05 && desc[1]==0x01);
    assert(desc[desc_len-1]==0xc0);
    assert(RM11_HID_REPORT_BYTES==14);
    sample(&p,report);
    assert(report[1]==0 && report[2]==0);
    assert(report[3]==8); /* neutral hat, not UP */
    assert(report[6]==0xff && report[7]==0xff); /* neutral inverted XInput Y = -1 */

    /* Exactly one HID button bit for every physical Xbox button. */
    static const uint16_t xbox[]={
        0x1000,0x2000,0x4000,0x8000,0x0100,
        0x0200,0x0020,0x0010,0x0040,0x0080
    };
    for(unsigned i=0;i<sizeof(xbox)/sizeof(xbox[0]);i++){
        p.buttons=xbox[i];sample(&p,report);
        uint16_t b=(uint16_t)report[1]|((uint16_t)report[2]<<8);
        assert(b==(uint16_t)(1u<<i));
    }
    const uint16_t dpad[]={1,9,8,10,2,6,4,5,3,0};
    const uint8_t hats[]={0,1,2,3,4,5,6,7,8,8};
    for(unsigned i=0;i<sizeof(dpad)/sizeof(dpad[0]);i++){
        p.buttons=dpad[i];sample(&p,report);
        assert(report[3]==hats[i]);
        assert(report[1]==0);
    }
    p.buttons=0x1000|0x2000|0x8000|0x0100|0x0009;
    p.lx=INT16_MIN;p.ly=INT16_MAX;p.rx=INT16_MAX;p.ry=INT16_MIN;
    p.lt=0;p.rt=255;
    sample(&p,report);
    assert(report[1]==(1|2|8|16)); /* A B Y LB */
    assert(report[3]==1); /* up-right */
    assert(report[4]==0 && report[5]==0x80); /* LX -32768 */
    assert(report[6]==0 && report[7]==0x80); /* LY inverted -32768 */
    assert(report[8]==0xff && report[9]==0x7f);
    assert(report[10]==0xff && report[11]==0x7f);
    assert(report[12]==0 && report[13]==255);
    assert(rm11_hid_encode(&s,report,13)==-1);
    assert(rm11_hid_encode(NULL,report,14)==-1);
    assert(rm11_hid_read(NULL,&s)==-1);
    p.connected=0;
    assert(rm11_hid_read(&p,&s)==0);
    assert(rm11_hid_encode(&s,report,14)==0);
    p.connected=1;p.sequence=3;
    assert(rm11_hid_read(&p,&s)==-1);
    p.sequence=4;p.magic=0;
    assert(rm11_hid_read(&p,&s)==-1);
    p.magic=RM11_HID_PAD_MAGIC;p.version=9;
    assert(rm11_hid_read(&p,&s)==-1);
    puts("RM11_HID_NATIVE_CONTRACT_16_BUTTONS_DPAD_6_AXES_SHARED_MMAP_PASS");
    return 0;
}
