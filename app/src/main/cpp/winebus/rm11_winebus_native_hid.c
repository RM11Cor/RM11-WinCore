/* Wine makedep: this source must NEVER be compiled as a Windows PE object.
 * Matching upstream Winebus unixlib.c and bus_sdl.c declarations. */
#if 0
#pragma makedep unix
#endif

/*
 * RM11 native Wine HID backend for pinned The412Banner/proton-wine
 * 256288853b206373cbf65b775143d33bb11035dd
 *
 * Built inside dlls/winebus.sys/winebus.so. Reuses existing sdl_* Unix-call
 * SLOT NUMBERS (the PE/unixlib ABI stays unchanged), but performs NO SDL_Init,
 * SDLActivity JNI calls, keyboard mapping, root or /dev/uinput operations.
 *
 * This file MUST NOT be packaged until a source-matched Wine Unix library
 * is built and tested with the signed PE winebus.sys.
 */
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../unix_private.h"
#include "rm11_native_hid_transport.h"

WINE_DEFAULT_DEBUG_CHANNEL(hid);

struct rm11_unix_device
{
    struct unix_device base;
    BOOL started;
};
static struct rm11_unix_device *rm11_device;
static struct list rm11_queue=LIST_INIT(rm11_queue);
static const rm11_shared_pad *rm11_shared;
static rm11_hid_bus rm11_bus;
static volatile int rm11_stop_requested;
static int rm11_native_mode;

static void rm11_debug(const char *stage)
{
    const char *path=getenv("RM11_NATIVE_HID_STATUS_PATH");
    int fd;
    if(!path || path[0]!='/' || strlen(path)>1000)return;
    fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd>=0){
        char line[160];
        int n=snprintf(line,sizeof(line),"RM11_WINE_NATIVE_HID=%s\n",stage);
        if(n>0 && n<(int)sizeof(line))write(fd,line,n);
        close(fd);
    }
}
static void rm11_destroy(struct unix_device *dev){(void)dev;}
static NTSTATUS rm11_start(struct unix_device *dev){
    ((struct rm11_unix_device *)dev)->started=TRUE;
    return STATUS_SUCCESS;
}
static void rm11_stop(struct unix_device *dev){
    ((struct rm11_unix_device *)dev)->started=FALSE;
}
static NTSTATUS rm11_get_desc(struct unix_device *dev,BYTE *buffer,
                              UINT cap,UINT *out_length){
    size_t length=0;
    const uint8_t *bytes=rm11_hid_descriptor(&length);
    (void)dev;
    if(!out_length)return STATUS_INVALID_PARAMETER;
    *out_length=(UINT)length;
    if(cap<length)return STATUS_BUFFER_TOO_SMALL;
    if(!buffer)return STATUS_INVALID_PARAMETER;
    memcpy(buffer,bytes,length);
    return STATUS_SUCCESS;
}
static void rm11_unsupported(struct unix_device *dev,
                              HID_XFER_PACKET *packet,IO_STATUS_BLOCK *io){
    (void)dev;(void)packet;
    if(io){io->Status=STATUS_NOT_SUPPORTED;io->Information=0;}
}
static const struct raw_device_vtbl rm11_vtbl={
    rm11_destroy,rm11_start,rm11_stop,
    rm11_get_desc,rm11_unsupported,rm11_unsupported,rm11_unsupported
};
static void copy_name(WCHAR *dst,size_t capacity,const char *source){
    size_t i=0;
    for(;i+1<capacity && source[i];i++)dst[i]=(WCHAR)(unsigned char)source[i];
    dst[i]=0;
}
static int rm11_register(void *context,uint16_t vid,uint16_t pid,
                         const uint8_t *report_desc,size_t length){
    struct device_desc desc={0};
    struct rm11_unix_device *dev;
    (void)context;(void)report_desc;(void)length;
    if(rm11_device)return 0;
    if(!(dev=raw_device_create(&rm11_vtbl,sizeof(*dev))))return -1;
    desc.vid=vid;desc.pid=pid;
    desc.version=0x0100;
    desc.input=0;
    desc.uid=0x524d3131;
    desc.bus_type=BUS_TYPE_USB;
    desc.is_gamepad=TRUE;
    desc.is_hidraw=FALSE;
    copy_name(desc.manufacturer,ARRAY_SIZE(desc.manufacturer),"RM11 WinCore");
    copy_name(desc.product,ARRAY_SIZE(desc.product),"RM11 Xbox Virtual Gamepad");
    copy_name(desc.serialnumber,ARRAY_SIZE(desc.serialnumber),"RM11PAD0001");
    if(!bus_event_queue_device_created(&rm11_queue,&dev->base,&desc)){
        free(dev);
        return -1;
    }
    rm11_device=dev;
    rm11_debug("PNP_GAMEPAD_CREATE_QUEUED");
    return 0;
}
static int rm11_send(void *context,const uint8_t *report,size_t length){
    (void)context;
    if(!rm11_device)return -1;
    if(!rm11_device->started)return -1; /* retry once PnP starts device */
    if(length>UINT16_MAX)return -1;
    return bus_event_queue_input_report(&rm11_queue,&rm11_device->base,
                                         (BYTE *)report,(USHORT)length)?0:-1;
}
static void rm11_remove(void *context){
    (void)context;
    if(!rm11_device)return;
    if(bus_event_queue_device_removed(&rm11_queue,&rm11_device->base))
        rm11_debug("PNP_GAMEPAD_REMOVE_QUEUED");
    rm11_device=NULL;
}
static const rm11_hid_transport rm11_sink={
    NULL,rm11_register,rm11_send,rm11_remove
};
static int rm11_enabled(void){
    const char *v=getenv("RM11_NATIVE_HID_BUS");
    return v && !strcmp(v,"1");
}
static NTSTATUS rm11_init(void *args){
    const char *filename=getenv("RM11_V49044_STATE_UNIXPATH");
    struct stat st;
    int fd;
    (void)args;
    memset(&rm11_bus,0,sizeof(rm11_bus));
    __atomic_store_n(&rm11_stop_requested,0,__ATOMIC_RELEASE);
    rm11_device=NULL;
    list_init(&rm11_queue);
    rm11_debug("NATIVE_BUS_ENTRY");
    if(!filename || filename[0]!='/' || strlen(filename)>1000){
        rm11_debug("STATE_PATH_INVALID");
        return STATUS_UNSUCCESSFUL;
    }
    fd=open(filename,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){rm11_debug("STATE_OPEN_FAILED");return STATUS_UNSUCCESSFUL;}
    if(fstat(fd,&st)<0 || st.st_size!=64){
        close(fd);rm11_debug("STATE_SIZE_INVALID");return STATUS_UNSUCCESSFUL;
    }
    rm11_shared=mmap(NULL,64,PROT_READ,MAP_SHARED,fd,0);
    close(fd);
    if(rm11_shared==MAP_FAILED){
        rm11_shared=NULL;rm11_debug("STATE_MAP_FAILED");return STATUS_UNSUCCESSFUL;
    }
    rm11_debug("STATE_MMAP_OK_NO_SDL_INIT");
    return STATUS_SUCCESS;
}
static NTSTATUS rm11_wait(void *args){
    struct bus_event *event=args;
    struct timespec ts={0,16000000}; /* max 62.5Hz, no busy-loop */
    while(!__atomic_load_n(&rm11_stop_requested,__ATOMIC_ACQUIRE)){
        bus_event_cleanup(event);
        event->type=BUS_EVENT_TYPE_NONE;
        if(bus_event_queue_pop(&rm11_queue,event))return STATUS_PENDING;
        if(rm11_shared)rm11_hid_bus_tick(&rm11_bus,rm11_shared,&rm11_sink);
        if(bus_event_queue_pop(&rm11_queue,event))return STATUS_PENDING;
        nanosleep(&ts,NULL);
    }
    rm11_hid_bus_stop(&rm11_bus,&rm11_sink);
    bus_event_queue_destroy(&rm11_queue);
    if(rm11_shared){munmap((void *)rm11_shared,64);rm11_shared=NULL;}
    rm11_debug("NATIVE_BUS_EXIT");
    return STATUS_SUCCESS;
}
static NTSTATUS rm11_request_stop(void *args){
    (void)args;
    __atomic_store_n(&rm11_stop_requested,1,__ATOMIC_RELEASE);
    return STATUS_SUCCESS;
}
/* Keep existing Wine PE/Unix call-slot order and all original SDL behavior
 * unless the user enables RM11_NATIVE_HID_BUS for this Wine game session. */
NTSTATUS rm11_winebus_init(void *args){
    rm11_native_mode=rm11_enabled();
    return rm11_native_mode?rm11_init(args):sdl_bus_init(args);
}
NTSTATUS rm11_winebus_wait(void *args){
    return rm11_native_mode?rm11_wait(args):sdl_bus_wait(args);
}
NTSTATUS rm11_winebus_stop(void *args){
    return rm11_native_mode?rm11_request_stop(args):sdl_bus_stop(args);
}
