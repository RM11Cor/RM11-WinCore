#!/usr/bin/env python3
"""Optional EXPERIMENTAL build of upstream Box64 as an Android arm64 executable.

Downloads pinned *upstream* MIT-licensed sources on CI. DOES NOT run x86/Windows
code or fetch arbitrary APK packages. A failed experiment leaves the existing
RM11 APK working and leaves no fake Box64 placeholder in the package.
"""
from pathlib import Path
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'app/src/main/jniLibs/arm64-v8a/librm11box64.so'
LICENSE = ROOT / 'app/src/main/assets/third_party/box64/LICENSE.txt'
PATCH_RECEIPT = ROOT / 'app/src/main/assets/third_party/box64/RM11-STARTUP-PATCH.txt'
# Official Box64 v0.4.4 release, pin the actual commit too to detect moved tags.
UPSTREAM = 'https://github.com/ptitSeb/box64.git'
TAG = 'v0.4.4'
COMMIT = '2f130fab1d6e1a4ee8a71dc60cfdfcc839ad192a'
NDK = '27.2.12479018'


def find_compiler():
    roots = []
    for env in ('RM11_NDK_HOME', 'ANDROID_NDK_HOME'):
        if os.environ.get(env):
            roots.append(Path(os.environ[env]))
    for env in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
        if os.environ.get(env):
            roots.append(Path(os.environ[env]) / 'ndk' / NDK)
    roots.append(Path.home() / 'Android/Sdk/ndk' / NDK)
    for root in roots:
        compiler = root / 'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        if compiler.is_file():
            return compiler
    return None


def verify_android_pie(path):
    """Only AArch64 dynamic PIE with Android linker is accepted for APK packaging."""
    with open(path, 'rb') as f:
        header = f.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
            raise RuntimeError('Not 64-bit little endian ELF')
        typ, machine = struct.unpack_from('<HH', header, 16)
        if typ != 3 or machine != 183:
            raise RuntimeError('Expected AArch64 ET_DYN PIE executable')
        phoff = struct.unpack_from('<Q', header, 32)[0]
        phsize = struct.unpack_from('<H', header, 54)[0]
        phnum = struct.unpack_from('<H', header, 56)[0]
        file_size = Path(path).stat().st_size
        if phsize < 56 or not 1 <= phnum <= 128 or phoff + phsize * phnum > file_size:
            raise RuntimeError('Corrupt/oversized ELF program headers')
        interp = None
        for i in range(phnum):
            f.seek(phoff + i * phsize)
            ph = f.read(56)
            if struct.unpack_from('<I', ph)[0] == 3:  # PT_INTERP
                offset, length = struct.unpack_from('<QQ', ph, 8)[0], struct.unpack_from('<Q', ph, 32)[0]
                if not 1 <= length <= 128 or offset + length > file_size:
                    raise RuntimeError('Invalid PT_INTERP')
                f.seek(offset)
                interp = f.read(length).rstrip(b'\0')
                break
        if interp != b'/system/bin/linker64':
            raise RuntimeError('Android /system/bin/linker64 required; glibc Linux build rejected')


def run(cmd, *, cwd=None, timeout=600):
    print('$', ' '.join(map(str, cmd)), flush=True)
    subprocess.run([str(x) for x in cmd], cwd=cwd, check=True, timeout=timeout)


def patch_android_glibc_startup(source):
    """V1.8 trial: expose BOTH bionic __libc_init and Box64's glibc CRT hook.

    Box64 v0.4.4 src/emu/entrypoint.c currently has these functions in
    mutually-exclusive ANDROID/#else branches. Its wrappedlibc_private.h
    nevertheless advertises __libc_start_main for Android, producing a missing
    my___libc_start_main at runtime. This tightly-pinned experiment leaves
    the upstream implementations intact; it does not emulate a Linux loader.
    """
    target = Path(source) / 'src/emu/entrypoint.c'
    before = target.read_text(encoding='utf-8')
    needle = '\n#else\nEXPORT int32_t my___libc_start_main('
    replacement = ('\n#endif\n#if 1 /* RM11-V1.8: include glibc startup on Android alongside bionic startup */\n'
                   'EXPORT int32_t my___libc_start_main(')
    if before.count(needle) != 1 or 'RM11-V1.8' in before:
        raise RuntimeError('Pinned Box64 startup source no longer matches expected v0.4.4 layout')
    if 'GOM(__libc_start_main, iFEpippppp)' not in (Path(source)/'src/wrapped/wrappedlibc_private.h').read_text(encoding='utf-8'):
        raise RuntimeError('Upstream libc wrapper contract changed: refuse unsafe patch')
    if '#ifdef ANDROID' not in before or 'my___libc_init' not in before:
        raise RuntimeError('Expected Android libc entrypoint missing')
    target.write_text(before.replace(needle, replacement, 1), encoding='utf-8')
    print('RM11 V1.8: Android bionic startup retained; Box64 glibc CRT bridge additionally compiled')



def patch_android_errno_bridge(source):
    """V2.1.3 EXPERIMENTAL: bridge glibc errno pointer to Android Bionic TLS.

    Upstream Box64 v0.4.4 libc wrapper registers __errno_location as a
    direct native symbol. Android's Bionic libc exports __errno() instead,
    leaving glibc x86-64 guests with an unresolved __errno_location.
    Only change this exact pinned signature, and generate a Box64 wrapped
    callback returning the caller thread's &errno, never a global integer.
    """
    source = Path(source)
    priv = source / 'src/wrapped/wrappedlibc_private.h'
    impl = source / 'src/wrapped/wrappedlibc.c'
    prev_private = priv.read_text(encoding='utf-8')
    prev_impl = impl.read_text(encoding='utf-8')
    old = 'GO(__errno_location, pFv)'
    new = 'GOM(__errno_location, pFEv)'
    if prev_private.count(old) != 1 or new in prev_private:
        raise RuntimeError('Pinned Box64 libc errno wrapper contract changed; refusing patch')
    anchor = '#include "generated/wrappedlibctypes.h"'
    if prev_impl.count(anchor) != 1 or 'RM11-V2.1.3-ERRNO' in prev_impl:
        raise RuntimeError('Pinned Box64 wrappedlibc.c insertion point changed; refusing patch')
    bridge = '''
/* RM11-V2.1.3-ERRNO: return the thread-local host errno pointer.
 * On Bionic, errno is a macro resolving through __errno(), unlike glibc's
 * __errno_location(). This is a small ABI experiment, NOT full glibc. */
EXPORT void* my___errno_location(x64emu_t* emu)
{
    (void)emu;
    return (void*)&errno;
}

'''
    priv.write_text(prev_private.replace(old, new, 1), encoding='utf-8')
    impl.write_text(prev_impl.replace(anchor, anchor + '\n' + bridge, 1), encoding='utf-8')
    print('RM11 V2.1.3: Android libc __errno_location guest wrapper now bridges to per-thread Bionic errno')

def patch_android_glibc_misc_bridges(source):
    """V2.1.4 experiment: resolve two GLIBC symbols absent from Android Bionic.

    Bionic exposes getdelim, but not the GNU-prefixed __getdelim alias.
    Its assert interface differs from glibc's __assert_fail. Keep the
    argument ordering, use Box64's FILE stream wrapper type S, and preserve
    normal glibc abort semantics. Does not imply Wine or full glibc support.
    """
    source = Path(source)
    priv = source / 'src/wrapped/wrappedlibc_private.h'
    impl = source / 'src/wrapped/wrappedlibc.c'
    old_private = priv.read_text(encoding='utf-8')
    old_impl = impl.read_text(encoding='utf-8')
    changes = {
        'GO(__assert_fail, vFppup)': 'GOM(__assert_fail, vFEppup)',
        'GOW(__getdelim, lFppiS)': 'GOM(__getdelim, lFEppiS)',
    }
    anchor = '#include "generated/wrappedlibctypes.h"'
    for old, new in changes.items():
        if old_private.count(old) != 1 or new in old_private:
            raise RuntimeError('Pinned Box64 missing exact glibc symbol definition: ' + old)
    if old_impl.count(anchor) != 1 or 'RM11-V2.1.4-GLIBC' in old_impl:
        raise RuntimeError('Pinned Box64 wrappedlibc.c insertion point changed; refusing patch')
    bridge = r'''
/* RM11-V2.1.4-GLIBC: Android Bionic compatibility experiment.
 * The GNU assert handler is absent as a native bionic libc export.
 * This is a noreturn handler; never claim that a failed assert succeeded. */
EXPORT void my___assert_fail(x64emu_t* emu, const char* expression,
                             const char* file, unsigned int line,
                             const char* function)
{
    (void)emu;
    fprintf(stderr, "Box64 guest assertion failed: %s (%s:%u, %s)\n",
            expression ? expression : "?", file ? file : "?", line,
            function ? function : "?");
    abort();
}

/* Android Bionic has getdelim() but not the glibc __getdelim alias.
 * Box64 wrapper signature uses S for the translated FILE* stream. */
EXPORT ssize_t my___getdelim(x64emu_t* emu, char** lineptr,
                              size_t* n, int delimiter, FILE* stream)
{
    (void)emu;
    return getdelim(lineptr, n, delimiter, stream);
}
'''
    updated_private = old_private
    for old, new in changes.items():
        updated_private = updated_private.replace(old, new, 1)
    priv.write_text(updated_private, encoding='utf-8')
    impl.write_text(old_impl.replace(anchor, anchor + '\n' + bridge, 1), encoding='utf-8')
    print('RM11 V2.1.4: GNU __assert_fail and __getdelim wrapped with Android Bionic-compatible functions')



def patch_android_nl_langinfo_codeset(source):
    """V2.2.3: translate glibc CODESET (14) to Android Bionic CODESET (1).

    The unmodified Box64 wrapper forwards glibc's numeric nl_item directly
    to Android Bionic's nl_langinfo. Bionic 14 is DAY_7 ('Saturday'), whereas
    Wine expects a charset like ASCII/UTF-8. Restrict this patch to CODESET;
    other glibc nl_item numbers still require separate compatibility work.
    """
    source = Path(source)
    priv=source/'src/wrapped/wrappedlibc_private.h'
    impl=source/'src/wrapped/wrappedlibc.c'
    before=priv.read_text(encoding='utf-8')
    code=impl.read_text(encoding='utf-8')
    old='GO(nl_langinfo, pFi)'
    new='GOM(nl_langinfo, pFEi)'
    insert='#include <errno.h>'
    mark='#include "generated/wrappedlibctypes.h"'
    if before.count(old)!=1 or new in before or code.count(insert)!=1 or code.count(mark)!=1 or 'RM11-V2.2.3-LANGINFO' in code:
        raise RuntimeError('Pinned Box64 nl_langinfo wrapper changed; refusing patch')
    bridge=r"""
/* RM11-V2.2.3-LANGINFO: Wine/glibc CODESET=14, Bionic CODESET=1.
 * Forwarding 14 to Bionic returns DAY_7 (Saturday), not an encoding. */
EXPORT char* my_nl_langinfo(x64emu_t* emu, int item)
{
    (void)emu;
#ifdef ANDROID
    if (item == 14) /* guest glibc CODESET */
        return nl_langinfo(CODESET); /* host Bionic CODESET */
#endif
    return nl_langinfo(item);
}
"""
    priv.write_text(before.replace(old,new,1),encoding='utf-8')
    code=code.replace(insert,insert+'\n#include <langinfo.h>',1)
    code=code.replace(mark,mark+'\n'+bridge,1)
    impl.write_text(code,encoding='utf-8')
    print('RM11 V2.2.3: guest glibc CODESET=14 mapped to host Android Bionic CODESET=1')


def patch_box64_child_heap_isolation(source):
    """Explicit opt-in Bionic heap-tag isolation in Box64 subprocess ONLY.

    No allocator behavior is changed for normal users; unsupported cases
    fail closed rather than pretending to diagnose/repair the bad free.
    """
    path=Path(source)/'src/main.c'
    before=path.read_text(encoding='utf-8')
    anchor='    x64emu_t* emu = NULL;'
    includes='#include "core.h"'
    if before.count(anchor)!=1 or before.count(includes)!=1 or 'RM11-HEAP-ISOLATION-V224' in before:
        raise RuntimeError('Pinned Box64 main.c changed; refusing scoped heap patch')
    preamble='''#include "core.h"
#ifdef ANDROID
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#endif'''
    addition=r'''    /* RM11-HEAP-ISOLATION-V224: opt-in isolated child process only.
     * Experimental: no pointer rewriting and no default security downgrade. */
#ifdef ANDROID
    const char* rm11_heap_probe = getenv("RM11_TEST_DISABLE_BIONIC_HEAP_TAGS");
    if (rm11_heap_probe && strcmp(rm11_heap_probe, "1") == 0) {
#if defined(M_BIONIC_SET_HEAP_TAGGING_LEVEL) && defined(M_HEAP_TAGGING_LEVEL_NONE)
        if (!mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_NONE)) {
            fprintf(stderr, "RM11_HEAP_ISOLATION_REJECTED: mallopt failed; Wine not launched\n");
            return 123;
        }
        fprintf(stderr, "RM11_HEAP_ISOLATION_APPLIED: child process ONLY; reduced checking for diagnostics\n");
#else
        fprintf(stderr, "RM11_HEAP_ISOLATION_UNSUPPORTED: Bionic malloc option unavailable\n");
        return 124;
#endif
    }
#endif
'''
    path.write_text(before.replace(includes,preamble,1).replace(anchor,addition+anchor,1),encoding='utf-8')
    print('RM11 V2.2.4: optional child Box64 Bionic heap-tag test patched')



def patch_rm11_owned_environment_snapshot(source):
    """New V2.3 ownership bridge, independently based on pinned upstream v0.4.4.

    The guest must never receive a Bionic-owned getenv pointer that it might
    mistakenly free. Return a stable snapshot and intercept free ONLY for our
    own borrowed snapshot addresses. Other allocations follow native free.
    Refuse changed upstream wrapper contracts instead of guessing.
    """
    source = Path(source)
    definitions = source / 'src/wrapped/wrappedlibc_private.h'
    implementation = source / 'src/wrapped/wrappedlibc.c'
    defs = definitions.read_text(encoding='utf-8')
    code = implementation.read_text(encoding='utf-8')
    before = ('GO2(__secure_getenv, pFp, getenv)   // not always present\n'
              'GOW(secure_getenv, pFp)')
    after = ('#ifdef ANDROID\n'
             'GOM(__secure_getenv, pFEp)\n'
             'GOM(secure_getenv, pFEp)\n'
             '#else\n' + before + '\n#endif')
    getenv_old='GO(getenv, pFp)'
    getenv_new='#ifdef ANDROID\nGOM(getenv, pFEp)\n#else\nGO(getenv, pFp)\n#endif'
    free_old='GO(free, vFp)'
    free_new='#ifdef ANDROID\nGOM(free, vFEp)\n#else\nGO(free, vFp)\n#endif'
    if defs.count(before)!=1 or defs.count(getenv_old)!=1 or defs.count(free_old)!=1 or 'RM11_ENV_SNAPSHOT' in code:
        raise RuntimeError('Box64 libc symbols no longer match pinned v0.4.4; refuse ownership patch')
    # Use a diagnostic-owned immutable snapshot. Never expose the Bionic env
    # buffer itself to the x86_64 guest. Keep snapshots for process lifetime,
    # as required by borrowed getenv semantics (not freeable by the caller).
    # The small, bounded cache records ownership; unrelated free goes to Bionic.
    include='#include <errno.h>'
    anchor='#include "generated/wrappedlibctypes.h"'
    if code.count(anchor)!=1 or code.count(include)!=1:
        raise RuntimeError('Unexpected Box64 C injection points')
    added = r'''
#ifdef ANDROID
/* RM11_ENV_SNAPSHOT_V230: borrowed pointer ownership isolation.
 * Snapshots stay alive until process exit. No raw Bionic env address crosses
 * the x86_64 ABI. This ONLY guards pointers allocated by this adapter.
 * This is NOT a general free/heap crash suppressor. */
#define RM11_ENV_MAX_ENTRIES 1024
#define RM11_ENV_MAX_BYTES (1024u * 1024u)
typedef struct rm11_env_entry {
    struct rm11_env_entry *next;
    char *name;
    char *snapshot;
    size_t bytes;
} rm11_env_entry;
static pthread_mutex_t rm11_env_mu = PTHREAD_MUTEX_INITIALIZER;
static rm11_env_entry *rm11_env_head = NULL;
static size_t rm11_env_count = 0;
static size_t rm11_env_bytes = 0;

EXPORT char* my_secure_getenv(x64emu_t* emu, const char* name)
{
    (void)emu;
    if (!name || !*name || strchr(name, '=')) return NULL;
    /* The pinned source defines secure_getenv -> getenv for Bionic. */
    const char *native_value = getenv(name);
    if (!native_value) return NULL;
    size_t n = strlen(name), v = strlen(native_value);
    if (n > 255 || v > 16384) {
        fprintf(stderr, "RM11_ENV_SNAPSHOT_LIMIT: oversized environment value\n");
        return NULL;
    }
    pthread_mutex_lock(&rm11_env_mu);
    rm11_env_entry *e;
    for (e = rm11_env_head; e; e = e->next) {
        if (!strcmp(e->name, name) && !strcmp(e->snapshot, native_value)) {
            char *borrowed = e->snapshot;
            pthread_mutex_unlock(&rm11_env_mu);
            return borrowed;
        }
    }
    if (rm11_env_count >= RM11_ENV_MAX_ENTRIES ||
        rm11_env_bytes + n + v + 2 > RM11_ENV_MAX_BYTES) {
        pthread_mutex_unlock(&rm11_env_mu);
        fprintf(stderr, "RM11_ENV_SNAPSHOT_LIMIT: cache full, lookup refused\n");
        return NULL;
    }
    e = (rm11_env_entry*)malloc(sizeof(*e));
    if (!e) { pthread_mutex_unlock(&rm11_env_mu); return NULL; }
    e->name = (char*)malloc(n + 1);
    e->snapshot = (char*)malloc(v + 1);
    if (!e->name || !e->snapshot) {
        free(e->name); free(e->snapshot); free(e);
        pthread_mutex_unlock(&rm11_env_mu);
        return NULL;
    }
    memcpy(e->name, name, n + 1);
    memcpy(e->snapshot, native_value, v + 1);
    e->bytes = n + v + 2;
    e->next = rm11_env_head;
    rm11_env_head = e;
    rm11_env_bytes += e->bytes;
    ++rm11_env_count;
    pthread_mutex_unlock(&rm11_env_mu);
    fprintf(stderr, "RM11_ENV_SNAPSHOT_CREATED: borrowed, immutable, process-owned\n");
    return e->snapshot;
}
EXPORT char* my___secure_getenv(x64emu_t* emu, const char* name)
{
    return my_secure_getenv(emu, name);
}
EXPORT char* my_getenv(x64emu_t* emu, const char* name)
{
    return my_secure_getenv(emu, name);
}
EXPORT void my_free(x64emu_t* emu, void *ptr)
{
    (void)emu;
    if (!ptr) return;
    pthread_mutex_lock(&rm11_env_mu);
    for (rm11_env_entry *e = rm11_env_head; e; e = e->next) {
        /* Wine/x86 guest code may have lost the Android top-byte tag.
         * Only recognize pointers that match one of OUR snapshots. */
        const uintptr_t addr_mask = UINT64_C(0x00ffffffffffffff);
        if (((uintptr_t)e->snapshot & addr_mask) == ((uintptr_t)ptr & addr_mask)) {
            pthread_mutex_unlock(&rm11_env_mu);
            fprintf(stderr, "RM11_ENV_BORROWED_FREE_PREVENTED: immutable env snapshot\n");
            return; /* free(getenv()) is invalid by the glibc contract. */
        }
    }
    pthread_mutex_unlock(&rm11_env_mu);
    free(ptr); /* ALL unrelated native allocations are freed normally. */
}
#endif
'''
    assert '#include <pthread.h>' not in code
    code=code.replace(include,include+'\n#include <pthread.h>\n#include <stdint.h>',1)
    code=code.replace(anchor,anchor+'\n'+added,1)
    definitions.write_text(defs.replace(before,after,1).replace(getenv_old,getenv_new,1).replace(free_old,free_new,1), encoding='utf-8')
    implementation.write_text(code,encoding='utf-8')
    print('RM11 V2.3: secure_getenv owned snapshot + exact-pointer guard; Bionic tagging unchanged')

def patch_android_glibc_ctype_loc(source):
    """V2.3.1: glibc ctype pointer-to-table ABI for Android/Bionic.

    Android Bionic does not export the glibc __ctype_{b,tolower,toupper}_loc
    symbols. The x86_64 ABI expects pointers to 384-entry tables, indexed
    through +128 and accessible as __ctype_b_loc()[0][c]. A C/POSIX ASCII
    bootstrap is provided; no claim is made of full per-thread glibc locales.
    """
    source=Path(source)
    priv=source/'src/wrapped/wrappedlibc_private.h'
    impl=source/'src/wrapped/wrappedlibc.c'
    declarations=priv.read_text(encoding='utf-8')
    code=impl.read_text(encoding='utf-8')
    symbols=('__ctype_b_loc','__ctype_tolower_loc','__ctype_toupper_loc')
    for symbol in symbols:
        old=f'GO({symbol}, pFv)'
        if declarations.count(old)!=1 or f'GOM({symbol}, pFEv)' in declarations:
            raise RuntimeError('Box64 ctype symbol contract changed: '+symbol)
        declarations=declarations.replace(old,
            '#ifdef ANDROID\nGOM('+symbol+', pFEv)\n#else\n'+old+'\n#endif',1)
    anchor='#include "generated/wrappedlibctypes.h"'
    if code.count(anchor)!=1 or 'RM11_CTYPE_BRIDGE_V231' in code:
        raise RuntimeError('Pinned Box64 ctype implementation location changed')
    bridge=r"""
#ifdef ANDROID
/* RM11_CTYPE_BRIDGE_V231: guest glibc ctype C-locale fallback.
 * x86_64 glibc tables have 384 entries and are biased by 128.
 * This is a static immutable POSIX/ASCII table, not glibc locale switching.
 * glibc _ISbit(N) is endian-converted for N<8 on little-endian x86.
 * Avoid Bionic ctype symbols because their binary ABI is incompatible. */
#define RM11_CTYPE_UPPER 0x0100u
#define RM11_CTYPE_LOWER 0x0200u
#define RM11_CTYPE_ALPHA 0x0400u
#define RM11_CTYPE_DIGIT 0x0800u
#define RM11_CTYPE_XDIGIT 0x1000u
#define RM11_CTYPE_SPACE 0x2000u
#define RM11_CTYPE_PRINT 0x4000u
#define RM11_CTYPE_GRAPH 0x8000u
#define RM11_CTYPE_BLANK 0x0001u
#define RM11_CTYPE_CNTRL 0x0002u
#define RM11_CTYPE_PUNCT 0x0004u
#define RM11_CTYPE_ALNUM 0x0008u
static unsigned short rm11_ctype_b_table[384];
static int32_t rm11_ctype_tolower_table[384];
static int32_t rm11_ctype_toupper_table[384];
static const unsigned short *rm11_ctype_b_ptr=rm11_ctype_b_table+128;
static const int32_t *rm11_ctype_tolower_ptr=rm11_ctype_tolower_table+128;
static const int32_t *rm11_ctype_toupper_ptr=rm11_ctype_toupper_table+128;
static pthread_once_t rm11_ctype_once=PTHREAD_ONCE_INIT;
static void rm11_init_ctype(void)
{
    for (int ch=-128; ch<=255; ++ch) {
        int k=ch+128;
        int c=(ch<0 && ch!=-1)?ch+256:ch;
        int upper=(c>='A' && c<='Z');
        int lower=(c>='a' && c<='z');
        int digit=(c>='0' && c<='9');
        int xdigit=digit || (c>='A' && c<='F') || (c>='a' && c<='f');
        int space=(c==' ' || (c>=9 && c<=13));
        int blank=(c==' ' || c=='\t');
        int print=(c>=32 && c<=126);
        int graph=(c>=33 && c<=126);
        int cntrl=(c>=0 && c<=31) || c==127;
        int punct=graph && !upper && !lower && !digit;
        unsigned short flags=0;
        if (upper) flags|=RM11_CTYPE_UPPER;
        if (lower) flags|=RM11_CTYPE_LOWER;
        if (upper || lower) flags|=RM11_CTYPE_ALPHA;
        if (digit) flags|=RM11_CTYPE_DIGIT;
        if (xdigit) flags|=RM11_CTYPE_XDIGIT;
        if (space) flags|=RM11_CTYPE_SPACE;
        if (print) flags|=RM11_CTYPE_PRINT;
        if (graph) flags|=RM11_CTYPE_GRAPH;
        if (blank) flags|=RM11_CTYPE_BLANK;
        if (cntrl) flags|=RM11_CTYPE_CNTRL;
        if (punct) flags|=RM11_CTYPE_PUNCT;
        if (upper || lower || digit) flags|=RM11_CTYPE_ALNUM;
        rm11_ctype_b_table[k]=flags;
        rm11_ctype_tolower_table[k]=(ch==-1)?-1:(upper?c+('a'-'A'):c);
        rm11_ctype_toupper_table[k]=(ch==-1)?-1:(lower?c-('a'-'A'):c);
    }
    fprintf(stderr, "RM11_CTYPE_BRIDGE_READY: x86_64 glibc C/ASCII tables\n");
}
EXPORT const unsigned short **my___ctype_b_loc(x64emu_t* emu)
{
    (void)emu;
    pthread_once(&rm11_ctype_once, rm11_init_ctype);
    return &rm11_ctype_b_ptr;
}
EXPORT const int32_t **my___ctype_tolower_loc(x64emu_t* emu)
{
    (void)emu;
    pthread_once(&rm11_ctype_once, rm11_init_ctype);
    return &rm11_ctype_tolower_ptr;
}
EXPORT const int32_t **my___ctype_toupper_loc(x64emu_t* emu)
{
    (void)emu;
    pthread_once(&rm11_ctype_once, rm11_init_ctype);
    return &rm11_ctype_toupper_ptr;
}
#endif /* RM11_CTYPE_BRIDGE_V231 */
"""
    if '#include <pthread.h>' in code:
        pass  # V2.3 ownership patch already inserts this header
    else:
        raise RuntimeError('V2.3 ownership prerequisite missing (pthread)')
    priv.write_text(declarations,encoding='utf-8')
    impl.write_text(code.replace(anchor,anchor+'\n'+bridge,1),encoding='utf-8')
    print('RM11 V2.3.1: ctype glibc x86_64 ABI bridged with bounded ASCII C-locale tables')


def build(compiler):
    with tempfile.TemporaryDirectory(prefix='rm11-upstream-box64-') as tmp:
        source = Path(tmp) / 'box64'
        builddir = Path(tmp) / 'build'
        run(['git', 'clone', '--depth', '1', '--branch', TAG, UPSTREAM, source], timeout=180)
        sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
        if sha != COMMIT:
            raise RuntimeError('Upstream tag moved! Actual commit: ' + sha)
        patch_android_glibc_startup(source)
        patch_android_errno_bridge(source)
        patch_android_glibc_misc_bridges(source)
        patch_android_nl_langinfo_codeset(source)
        patch_box64_child_heap_isolation(source)
        patch_rm11_owned_environment_snapshot(source)
        patch_android_glibc_ctype_loc(source)
        run(['cmake', '-S', source, '-B', builddir,
             f'-DCMAKE_C_COMPILER={compiler}', '-DARM64=ON', '-DANDROID=ON',
             '-DARM_DYNAREC=ON', '-DBAD_SIGNAL=ON', '-DTERMUX=OFF',
             '-DHAVE_TRACE=OFF', '-DNOBOX64=OFF', '-DNOGIT=ON',
             '-DCMAKE_BUILD_TYPE=Release'], timeout=180)
        run(['cmake', '--build', builddir, '--target', 'box64', '--parallel', '2'], timeout=960)
        binary = builddir / 'box64'
        verify_android_pie(binary)
        if binary.stat().st_size > 80 * 1024 * 1024:
            raise RuntimeError('Unexpected huge Box64 executable')
        source_license = source / 'LICENSE'
        if 'MIT License' not in source_license.read_text(encoding='utf-8'):
            raise RuntimeError('Expected upstream MIT license missing')
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        LICENSE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, TARGET)
        shutil.copy2(source_license, LICENSE)
        PATCH_RECEIPT.write_text('RM11 V1.8 trial: Box64 v0.4.4 pinned startup dual-entry patch applied at build.\n'
                                 'Source: src/emu/entrypoint.c; Android __libc_init retained; glibc __libc_start_main included.\n'
                                 'RM11 V2.1.3: libc errno wrapper patched via my___errno_location to Android TLS &errno.\n'
                                 'RM11 V2.1.4: glibc __assert_fail and __getdelim wrapper bridges added for Bionic.\n'
                                 'RM11 V2.2.3: nl_langinfo(CODESET) guest 14 -> Bionic CODESET 1.\n'
                                 'RM11 V2.2.4: opt-in child-only heap-tag A/B diagnostic, default tagging retained.\n'
                                 'RM11 V2.3: secure_getenv borrowed snapshot and exact ownership guard (new independent path).\n'
                                 'RM11 V2.3.1: glibc ctype_b/tolower/toupper_loc Android ABI adapters (ASCII C-locale).\n'
                                 'Build-time patch only; successful runtime behavior NOT guaranteed.\n', encoding='utf-8')
        print(f'PASS: genuine upstream Box64 {TAG} Android PIE packaged: {TARGET.stat().st_size} bytes')
        print('LIMIT: version probe ONLY, no Linux rootfs/Wine/x86 executable support guaranteed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--required', action='store_true',
                        help='Fail CI if experimental compilation fails')
    args = parser.parse_args()
    # Never leave an old binary from prior builds on disk on a failed experiment.
    TARGET.unlink(missing_ok=True)
    LICENSE.unlink(missing_ok=True)
    PATCH_RECEIPT.unlink(missing_ok=True)
    compiler = find_compiler()
    if compiler is None:
        print('SKIP: Android NDK unavailable. No upstream Box64 in this APK.')
        if args.required:
            raise SystemExit(2)
        return
    try:
        build(compiler)
    except (OSError, RuntimeError, subprocess.SubprocessError) as ex:
        TARGET.unlink(missing_ok=True)
        LICENSE.unlink(missing_ok=True)
        PATCH_RECEIPT.unlink(missing_ok=True)
        print('WARN: upstream Box64 Android experimental build failed:', ex, file=sys.stderr)
        print('The RM11 APK will still build, without Box64. Do NOT claim it was integrated.', file=sys.stderr)
        if args.required:
            raise


if __name__ == '__main__':
    main()
