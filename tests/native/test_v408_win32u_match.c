/* Host test for the exact trusted path grammar used by v4.0.8. */
#include <assert.h>
#include <stdio.h>
#include "wine_win32u_match_v408.h"
int main(void) {
    const char *virtual_ntdll =
      "/data/user/0/com.rm11.autocore/files/wine/lib/wine/aarch64-unix/ntdll.so";
    const char *real_ntdll =
      "/data/user/0/com.rm11.autocore/files/imagefs/wine/lib/wine/aarch64-unix/ntdll.so";
    assert(rm11_v408_win32u_match("win32u.so",virtual_ntdll,real_ntdll)==1);
    assert(rm11_v408_win32u_match(
      "/data/user/0/com.rm11.autocore/files/wine/lib/wine/aarch64-unix/win32u.so",
      virtual_ntdll,real_ntdll)==2);
    assert(rm11_v408_win32u_match(
      "/data/user/0/com.rm11.autocore/files/imagefs/wine/lib/wine/aarch64-unix/win32u.so",
      virtual_ntdll,real_ntdll)==3);
    assert(rm11_v408_win32u_match("/sdcard/game/win32u.so",virtual_ntdll,real_ntdll)==0);
    assert(rm11_v408_win32u_match("/tmp/win32u.so",virtual_ntdll,real_ntdll)==0);
    assert(rm11_v408_win32u_match("winex11.so",virtual_ntdll,real_ntdll)==0);
    assert(rm11_v408_win32u_match("libfreetype.so",virtual_ntdll,real_ntdll)==0);
    assert(rm11_v408_win32u_match("win32u.so","/tmp/not-ntdll",real_ntdll)==0);
    assert(rm11_v408_win32u_match("win32u.so",NULL,real_ntdll)==0);
    assert(rm11_v408_win32u_match(NULL,virtual_ntdll,real_ntdll)==0);
    assert(rm11_v408_win32u_match("win32u.so",virtual_ntdll,NULL)==1);
    puts("RM11_V408_WIN32U_TRUSTED_REQUEST_MATCH_TEST_PASS");
    return 0;
}
