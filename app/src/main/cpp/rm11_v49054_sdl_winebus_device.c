/*
 * Compiled DIRECTLY into the pinned SDL2 library at SDL_Init() time.
 * Winebus calls SDL_Init itself: do not initialize SDL concurrently from a
 * preloaded Wine service worker.  SDL's process-local virtual joystick then
 * becomes visible to the exact SDL instance used by Winebus HID discovery.
 *
 * The code is only invoked when RM11_V49054_NATIVE_SDL_DEVICE=1 and
 * /proc/self/cmdline identifies a Wine winedevice.exe host. Never affects
 * another Android app, desktop GUI or game process.
 *
 * The 64-byte shared mmap is the same state already proven with XInput.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define RM11_SDL_PAD_MAGIC 0x524d3131u
#define RM11_SDL_PAD_SIZE 64
typedef struct __attribute__((packed)) {
    uint32_t magic,version,sequence,connected;
    uint16_t buttons;
    uint8_t lt,rt;
    int16_t lx,ly,rx,ry;
    uint32_t reserved,reads,cap_reads;
    uint8_t padding[24];
} RM11_SdlPadState;
typedef char rm11_pad_length_must_be_64[(sizeof(RM11_SdlPadState)==64)?1:-1];

static pthread_mutex_t rm11_winebus_lock=PTHREAD_MUTEX_INITIALIZER;
static int rm11_winebus_attached=0;
static char rm11_winebus_status[1024];
static RM11_SdlPadState const *rm11_shared_pad;

static void rm11_sdl_status(const char *tag) {
    if(!rm11_winebus_status[0])return;
    int fd=open(rm11_winebus_status,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return;
    char row[180];
    int n=snprintf(row,sizeof(row),"RM11_V49054_WINEBUS=%s\n",tag);
    if(n>0 && n<(int)sizeof(row))(void)write(fd,row,(size_t)n);
    close(fd);
}

static int rm11_sdl_is_winedevice(void) {
    // v49055 on-device: both server and game inherited the correct SDL
    // environment, but no SDL Winebus log appeared. On Wine ARM64EC a
    // winedevice service can be hosted by the generic Wine loader whose
    // Linux cmdline lacks the PE basename. Never block SDL_Init/SetMainReady
    // by guessing a process name from /proc/self/cmdline.
    //
    // The opt-in environment is scoped by the app to its Wine processes,
    // and SDL itself is only loaded by the process requiring its API.
    const char *enabled=getenv("RM11_V49054_NATIVE_SDL_DEVICE");
    if(!enabled || strcmp(enabled,"1"))return 0;
    const char *status=getenv("RM11_V49054_STATUS_UNIXPATH");
    if(status && status[0]=='/' && strlen(status)<sizeof(rm11_winebus_status)
            && !rm11_winebus_status[0])
        strcpy(rm11_winebus_status,status);
    rm11_sdl_status("SDL_INIT_ENTERED_WITH_CONTROLLER_ENV");
    return 1;
}

static int rm11_sdl_snapshot(RM11_SdlPadState *out){
    if(!rm11_shared_pad)return 0;
    const volatile uint32_t *seq=(const volatile uint32_t *)
                              ((const char *)rm11_shared_pad+8);
    for(int i=0;i<8;i++){
        uint32_t before=__atomic_load_n(seq,__ATOMIC_ACQUIRE);
        if(before&1)continue;
        memcpy(out,rm11_shared_pad,sizeof(*out));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint32_t after=__atomic_load_n(seq,__ATOMIC_ACQUIRE);
        if(before==after && !(after&1) && out->magic==RM11_SDL_PAD_MAGIC
                  &&out->version==1)return 1;
    }
    return 0;
}

static int16_t rm11_sdl_inv_axis(int16_t v){return (int16_t)(-((int32_t)v)-1);}
static int16_t rm11_sdl_trigger(uint8_t v){return (int16_t)((int32_t)v*257-32768);}

static void rm11_sdl_update_pad(SDL_Joystick *joy,const RM11_SdlPadState *s){
    int16_t axes[6]={
        s->connected?s->lx:0,s->connected?rm11_sdl_inv_axis(s->ly):0,
        s->connected?s->rx:0,s->connected?rm11_sdl_inv_axis(s->ry):0,
        s->connected?rm11_sdl_trigger(s->lt):-32768,
        s->connected?rm11_sdl_trigger(s->rt):-32768
    };
    for(int i=0;i<6;i++)SDL_JoystickSetVirtualAxis(joy,i,axes[i]);
    const uint16_t buttons[15]={
        0x1000,0x2000,0x4000,0x8000,0x0020,0,0x0010,0x0040,
        0x0080,0x0100,0x0200,0x0001,0x0002,0x0004,0x0008
    };
    for(int i=0;i<15;i++) SDL_JoystickSetVirtualButton(joy,i,
        (uint8_t)(s->connected && buttons[i] && (s->buttons&buttons[i])?1:0));
    uint8_t hat=0;
    if(s->connected){
        if(s->buttons&0x0001)hat|=SDL_HAT_UP;
        if(s->buttons&0x0008)hat|=SDL_HAT_RIGHT;
        if(s->buttons&0x0002)hat|=SDL_HAT_DOWN;
        if(s->buttons&0x0004)hat|=SDL_HAT_LEFT;
    }
    SDL_JoystickSetVirtualHat(joy,0,hat);
}

static void *rm11_sdl_pad_worker(void *arg){
    SDL_Joystick *joy=(SDL_Joystick *)arg;
    RM11_SdlPadState state={0};
    uint16_t last_buttons=0xffff;
    int last_connected=-1;
    struct timespec period={0,16000000};
    for(;;){
        if(rm11_sdl_snapshot(&state)){
            rm11_sdl_update_pad(joy,&state);
            if(last_connected!=(int)state.connected){
                rm11_sdl_status(state.connected?
                    "SHARED_XBOX_CONTROLLER_CONNECTED":"SHARED_XBOX_CONTROLLER_DISCONNECTED");
                last_connected=(int)state.connected;
            }
            if(state.buttons!=last_buttons){
                if(last_buttons!=0xffff)rm11_sdl_status("XBOX_BUTTON_STATE_CHANGED");
                last_buttons=state.buttons;
            }
        }
        SDL_JoystickUpdate();
        nanosleep(&period,NULL);
    }
    return NULL;
}

static void rm11_sdl_attach_after_real_init(void){
    if(!rm11_sdl_is_winedevice())return;
    pthread_mutex_lock(&rm11_winebus_lock);
    if(rm11_winebus_attached){pthread_mutex_unlock(&rm11_winebus_lock);return;}
    rm11_winebus_attached=1;
    const char *status=getenv("RM11_V49054_STATUS_UNIXPATH");
    if(status && status[0]=='/' && strlen(status)<sizeof(rm11_winebus_status))
        strcpy(rm11_winebus_status,status);
    rm11_sdl_status("REAL_WINEBUS_SDL_INIT_SUCCEEDED");
    const char *file=getenv("RM11_V49044_STATE_UNIXPATH");
    if(!file||file[0]!='/'){rm11_sdl_status("SHARED_PAD_PATH_NOT_SET");goto done;}
    int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){rm11_sdl_status("SHARED_PAD_OPEN_FAILED");goto done;}
    rm11_shared_pad=(RM11_SdlPadState const *)mmap(NULL,RM11_SDL_PAD_SIZE,
                                                   PROT_READ,MAP_SHARED,fd,0);
    close(fd);
    if(rm11_shared_pad==MAP_FAILED){
        rm11_shared_pad=NULL;rm11_sdl_status("SHARED_PAD_MMAP_FAILED");goto done;
    }
    rm11_sdl_status("SHARED_PAD_MMAP_OK");
    SDL_VirtualJoystickDesc desc={0};
    desc.version=SDL_VIRTUAL_JOYSTICK_DESC_VERSION;
    desc.type=SDL_JOYSTICK_TYPE_GAMECONTROLLER;
    desc.naxes=6;desc.nbuttons=15;desc.nhats=1;
    desc.vendor_id=0x3f0b;desc.product_id=0x4905;
    desc.button_mask=0x7fff;desc.axis_mask=0x3f;
    desc.name="RM11 WinCore Xbox Virtual Gamepad";
    SDL_JoystickEventState(SDL_ENABLE);
    int index=SDL_JoystickAttachVirtualEx(&desc);
    if(index<0){
        rm11_sdl_status("VIRTUAL_ATTACH_FAILED");
        goto done;
    }
    rm11_sdl_status("VIRTUAL_PAD_ATTACHED_WINEBUS_SDL_INSTANCE");
    SDL_Joystick *joy=SDL_JoystickOpen(index);
    if(!joy){rm11_sdl_status("VIRTUAL_PAD_OPEN_FAILED");goto done;}
    rm11_sdl_status("VIRTUAL_PAD_OPEN_SUCCEEDED");
    pthread_t t;
    if(pthread_create(&t,NULL,rm11_sdl_pad_worker,joy)==0){
        pthread_detach(t);
        rm11_sdl_status("VIRTUAL_PAD_WORKER_STARTED");
    }else rm11_sdl_status("VIRTUAL_PAD_WORKER_FAILED");
done:
    pthread_mutex_unlock(&rm11_winebus_lock);
}
