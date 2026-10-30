/*
 * RM11 SDL2 virtual gamepad transport (v49044).
 * Independent bridge for the pinned Winebus SDL backend; not enabled for games.
 * This ELF must load in the process owning Winebus SDL, because SDL virtual
 * joysticks are process-local. Merely attaching here is NOT Windows detection.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>

#define RM11_MAGIC 0x524d3131u
#define RM11_SIZE 64u
#define SDL_JOYSTICK_SUBSYSTEM 0x200u
typedef struct SDL_Joystick SDL_Joystick;
typedef struct {
    uint16_t version,type,naxes,nbuttons,nhats,vendor_id,product_id,padding;
    uint32_t button_mask,axis_mask;
    const char *name;
    void *userdata;
    void (*Update)(void *);
    void (*SetPlayerIndex)(void *,int);
    int (*Rumble)(void *,uint16_t,uint16_t);
    int (*RumbleTriggers)(void *,uint16_t,uint16_t);
    int (*SetLED)(void *,uint8_t,uint8_t,uint8_t);
    int (*SendEffect)(void *,const void *,int);
} RM11_SDLVirtualJoystickDesc;
typedef struct __attribute__((packed)){
    uint32_t magic,version;
    uint32_t sequence,connected;
    uint16_t buttons;
    uint8_t lt,rt;
    int16_t lx,ly,rx,ry;
    uint32_t reserved,reads,capReads;
    uint8_t padding[24];
} RM11_Pad;
typedef char static_pad_64[(sizeof(RM11_Pad)==RM11_SIZE)?1:-1];

static const RM11_Pad *state;
static char status_path[1024];
static void report(const char *text) {
    if(!status_path[0])return;
    int fd=open(status_path,O_CREAT|O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0)return;
    char line[230];
    int n=snprintf(line,sizeof(line),"RM11_V49044_SDL_BUS=%s\n",text);
    if(n>0 && n<(int)sizeof(line))(void)write(fd,line,(size_t)n);
    close(fd);
}
static int snapshot(RM11_Pad *out) {
    if(!state)return 0;
    /* mmap is page-aligned, sequence starts at 8. Access the atomic through
     * an explicitly aligned offset rather than &packed_member (clang rejects
     * packed member atomic pointers, even when this concrete offset is safe). */
    const volatile uint32_t *seq=(const volatile uint32_t *)((const char *)state+8);
    if(((uintptr_t)seq & 3u)!=0)return 0;
    for(int i=0;i<8;i++){
        uint32_t before=__atomic_load_n(seq,__ATOMIC_ACQUIRE);
        if(before&1)continue;
        memcpy(out,(const void *)state,sizeof(*out));
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint32_t after=__atomic_load_n(seq,__ATOMIC_ACQUIRE);
        if(before==after && !(after&1) &&
           out->magic==RM11_MAGIC && out->version==1)return 1;
    }
    return 0;
}
typedef int (*SDL_InitSubSystem_t)(uint32_t);
typedef int (*SDL_Attach_t)(const RM11_SDLVirtualJoystickDesc *);
typedef SDL_Joystick *(*SDL_Open_t)(int);
typedef int (*SDL_Axis_t)(SDL_Joystick *,int,int16_t);
typedef int (*SDL_Button_t)(SDL_Joystick *,int,uint8_t);
typedef int (*SDL_Hat_t)(SDL_Joystick *,int,uint8_t);
typedef void (*SDL_Update_t)(void);
static SDL_InitSubSystem_t init_subsystem;
static SDL_Attach_t attach;
static SDL_Open_t joy_open;
static SDL_Axis_t set_axis;
static SDL_Button_t set_button;
static SDL_Hat_t set_hat;
static SDL_Update_t joy_update;
static int16_t invert_axis(int16_t v) {return (int16_t)(-((int32_t)v)-1);}
static int16_t trigger_axis(uint8_t v){return (int16_t)((int32_t)v*257-32768);}
static void drive(SDL_Joystick *joy,const RM11_Pad *s){
    const int16_t axes[6]={
        s->connected?s->lx:0,s->connected?invert_axis(s->ly):0,
        s->connected?s->rx:0,s->connected?invert_axis(s->ry):0,
        s->connected?trigger_axis(s->lt):-32768,
        s->connected?trigger_axis(s->rt):-32768
    };
    for(int i=0;i<6;i++)set_axis(joy,i,axes[i]);
    /* SDL_GameController button order A,B,X,Y,Back,Guide,Start,L3,R3,LB,RB,Dpad. */
    const uint16_t masks[15]={
        0x1000,0x2000,0x4000,0x8000,0x0020,0,0x0010,0x0040,
        0x0080,0x0100,0x0200,0x0001,0x0002,0x0004,0x0008
    };
    for(int i=0;i<15;i++)
        set_button(joy,i,(uint8_t)(s->connected && masks[i] &&
                               (s->buttons&masks[i])?1:0));
    uint8_t hat=0;
    if(s->connected){
        if(s->buttons&0x0001)hat|=1;  /* up */
        if(s->buttons&0x0008)hat|=2;  /* right */
        if(s->buttons&0x0002)hat|=4;  /* down */
        if(s->buttons&0x0004)hat|=8;  /* left */
    }
    set_hat(joy,0,hat);
}
static void *work(void *unused){
    (void)unused;
    const char *file=getenv("RM11_V49044_STATE_UNIXPATH");
    if(!file || file[0]!='/'){report("STATE_PATH_MISSING");return NULL;}
    int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){report("STATE_OPEN_FAILED");return NULL;}
    state=(const RM11_Pad *)mmap(NULL,RM11_SIZE,PROT_READ,MAP_SHARED,fd,0);
    close(fd);
    if(state==MAP_FAILED){state=NULL;report("STATE_MMAP_FAILED");return NULL;}
    /* Winebus normally dlopens the versioned SDL2 SONAME. Load our exact
     * signed APK SDL2 first; its SONAME is aliased in imagefs/usr/lib. */
    const char *apk_sdl=getenv("RM11_V49046_SDL2_ABSOLUTE");
    /* Prefer the exact SONAME that winebus.so dlopens. Attaching a virtual
     * device to a separately loaded SDL2 instance is invisible to Winebus. */
    void *lib=NULL;
    const char *libs[]={"libSDL2-2.0.so.0","libSDL2-2.0.so","libSDL2.so"};
    for(size_t i=0;i<3 && !lib;i++)lib=dlopen(libs[i],RTLD_NOW|RTLD_GLOBAL);
    if(lib)report("SDL_SONAME_REUSED_FOR_WINEBUS");
    if(!lib && apk_sdl && apk_sdl[0]=='/'){
        lib=dlopen(apk_sdl,RTLD_NOW|RTLD_GLOBAL);
        if(lib)report("SDL_ABSOLUTE_FALLBACK_NOT_WINEBUS_SHARING_PROOF");
    }
    if(!lib){report("SDL2_SONAME_NOT_FOUND");return NULL;}
    report("SDL2_SIGNED_LIBRARY_LOADED");
#define RESOLVE(var,name) do{ \
    *(void **)(&(var))=dlsym(lib,name); \
    if(!(var)){report("SDL2_REQUIRED_SYMBOL_MISSING");return NULL;} \
}while(0)
    RESOLVE(init_subsystem,"SDL_InitSubSystem");
    RESOLVE(attach,"SDL_JoystickAttachVirtualEx");
    RESOLVE(joy_open,"SDL_JoystickOpen");
    RESOLVE(set_axis,"SDL_JoystickSetVirtualAxis");
    RESOLVE(set_button,"SDL_JoystickSetVirtualButton");
    RESOLVE(set_hat,"SDL_JoystickSetVirtualHat");
    RESOLVE(joy_update,"SDL_JoystickUpdate");
#undef RESOLVE
    if(init_subsystem(SDL_JOYSTICK_SUBSYSTEM)!=0){
        report("SDL_JOYSTICK_INIT_FAILED");return NULL;
    }
    RM11_SDLVirtualJoystickDesc d={0};
    d.version=1;
    d.type=1;                 /* SDL_JOYSTICK_TYPE_GAMECONTROLLER */
    d.naxes=6;d.nbuttons=15;d.nhats=1;
    d.vendor_id=0x3f0b;d.product_id=0x4904; /* distinct RM11 virtual pad */
    d.button_mask=0x7fff;
    d.axis_mask=0x3f;
    d.name="RM11 WinCore Virtual Controller";
    int index=attach(&d);
    if(index<0){report("SDL_ATTACH_VIRTUAL_FAILED");return NULL;}
    SDL_Joystick *joystick=joy_open(index);
    if(!joystick){report("SDL_OPEN_VIRTUAL_FAILED");return NULL;}
    report("SDL_VIRTUAL_ATTACHED_IN_UNIX_PROCESS_NOT_WINE_ENUM_PROOF");
    RM11_Pad pad={0};
    struct timespec step={0,16000000};
    for(;;){
        if(snapshot(&pad))drive(joystick,&pad);
        joy_update();
        nanosleep(&step,NULL);
    }
    return NULL;
}
/* The SDL joystick is local to the process that runs Winebus.
 * Probe/game loader attachment is never enough. Restrict to service hosts;
 * do NOT spin an SDL worker inside wineserver, the game, or an X11 process. */
static int is_winebus_host(void){
    char cmd[4096]={0};
    int fd=open("/proc/self/cmdline",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 0;
    ssize_t n=read(fd,cmd,sizeof(cmd)-1);
    close(fd);
    if(n<=0)return 0;
    for(ssize_t i=0;i<n;i++)if(!cmd[i])cmd[i]=' ';
    /* Kernel drivers such as winebus.sys live in Wine's winedevice.exe,
     * NOT services.exe / svchost.exe. Injecting there only creates an SDL
     * joystick in the wrong process, invisible to Winebus and to all games.
     * Some Wine versions may have a distinct winebus.exe driver host. */
    return strstr(cmd,"winedevice.exe")!=NULL
        ||strstr(cmd,"winebus.exe")!=NULL;
}
__attribute__((constructor))static void start_bridge(void){
    const char *enabled=getenv("RM11_V49044_BUS_ENABLE");
    if(!enabled||strcmp(enabled,"1"))return;
    const char *path=getenv("RM11_V49044_STATUS_UNIXPATH");
    if(path && path[0]=='/' && strlen(path)<sizeof(status_path))
        strcpy(status_path,path);
    if(getenv("RM11_V49045_REQUIRE_WINEBUS_HOST") && !is_winebus_host()){
        /* Silence per-process logs so GPU and application processes remain untouched. */
        return;
    }
    char identified[90];
    snprintf(identified,sizeof(identified),
        "WINEDRIVER_HOST_CONSTRUCTOR_PID=%ld",(long)getpid());
    report(identified);
    pthread_t thread;
    if(pthread_create(&thread,NULL,work,NULL)==0)pthread_detach(thread);
    else report("WORKER_THREAD_FAILED");
}
