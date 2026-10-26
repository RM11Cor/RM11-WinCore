/*
 * RM11 Win64 persistent GUI diagnostic.
 *
 * This creates a genuinely interactive Win32 modal dialog. It remains on the
 * screen until the user presses OK (unlike rm11-gui-smoke-v271, which exits
 * immediately). It does not read/write files or depend on game assets.
 *
 * Build with pinned llvm-mingw x86_64-w64-mingw32-clang, not Android's ABI.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void WINAPI RM11Entry(void) {
    int button = MessageBoxW(
            NULL,
            L"RM11 Win64 GUI probe is running.\n\n"
            L"If you can read this window, Wine's Win64 user32 graphics "
            L"path displayed a real dialog.\n\n"
            L"Press OK to close this test.",
            L"RM11 Win64 GUI — visible window test",
            MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    ExitProcess(button == IDOK ? 60u : 62u);
}
