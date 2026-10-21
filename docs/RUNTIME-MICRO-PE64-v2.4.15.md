# RM11 v2.4.15: bounded PE64-to-ARM64 smoke test

This is a **limited, genuine PE32+ entry-point translation experiment** inside
RM11's native Android library. The included 1024-byte valid PE64 executable has
no Windows API imports and consists of x86-64 EAX arithmetic instructions.
The translator decodes six opcode patterns, emits AArch64 code, applies W^X
memory permissions, and calls that function only on ARM64. Result should be 42.

**THIS IS NOT FEXCORE, A WINE BACKEND, OR A COMPATIBLE WINDOWS GAME RUNTIME.**
No Linux guest syscalls, Win32 APIs, external PE execution, relocations,
imports, D3D, graphics, filesystem redirection or games are supported.
No existing game files are copied or modified.

The native host unit tests reject corrupt PE input, 32-bit PE, imports,
invalid entrypoints, unsupported x86 instructions and incomplete code.

Next: package an Android-compatible FEXCore (upstream license/audit required),
then integrate Wine/Proton with actual process/Win32 support before advertising
EXE or game compatibility. Hold 2.4.14 as known-good fallback.
