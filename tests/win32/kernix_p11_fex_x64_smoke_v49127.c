/* Signed-source, headless Windows x64 PE to qualify actual Wine/FEX guest
 * process creation. No game files, GPU, network, filesystem writes or input.
 * Exact exit 47 plus a stdout marker are both required for a PASS. */
#include <windows.h>
int main(void) {
    static const char message[]="KERNIX_P11_FEX64_WIN32_OK\n";
    DWORD written=0;
    HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
    if(output==NULL || output==INVALID_HANDLE_VALUE)return 49;
    if(!WriteFile(output,message,(DWORD)(sizeof(message)-1),&written,NULL)
       ||written!=(DWORD)(sizeof(message)-1))return 48;
    return 47;
}
