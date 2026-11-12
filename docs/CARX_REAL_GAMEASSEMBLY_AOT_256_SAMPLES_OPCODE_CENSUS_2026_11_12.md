# CarX Street PC — real GameAssembly PE code sample census and recompiler plan

2026-11-12, branch carx-street-pc-port-v1. The owner explicitly provided a
small PortLab v1.0 ZIP with privately owned original Windows x64 PE function
regions. This public document contains NO original game code bytes, no
function disassemblies, no proprietary C++ translations, and no DLLs.

## Proven incoming source evidence

- Owner original GameAssembly.dll: Windows PE32+ x86-64, 142,049,792 bytes.
- Extraction source: PE Win64 Exception Directory RUNTIME_FUNCTION data.
- PE exception entries reported: 412,001; small 4..320-byte executable
  regions eligible for sampling: 341,700.
- Source ZIP: 256 selected real machine-code region samples,
  33,153 total code bytes; 256/256 SHA-256 checks matched manifest.
- GNU objdump i386:x86-64 initial linear disassembly: 8,181 instruction-like
  entries. Linear disassembly can count padding/data as instructions;
  it is not a verified control-flow graph.
- Common mnemonics: MOV 3,259, CALL 942, LEA 417, JNE 374,
  TEST 341, CMP 326, XOR 262, MOVUPS 239, ADD 230, SUB 214.
- Samples with a branch/call outside their tiny sample: 241/256.
- Samples with RIP-relative memory addressing: 134/256.
- Samples without a decoded RET: 112/256.
- Samples containing INT3 bytes: 82/256.
- Samples with SIMD/XMM-like code: 80/256.
- Samples with additional unsupported common opcodes: ~50/256.
  These feature counts overlap.
- Nine samples appeared free of these coarse blockers, but review
  showed they are primarily stack-restoring epilogues and cold fragments,
  not callable standalone gameplay methods.

## Why this changes engineering priorities

Our initial Android PortLab extractor selected random small PE exception
regions. A RUNTIME_FUNCTION region often represents only a fragment,
unwind/cold path or epilogue. It does NOT prove a complete Unity IL2CPP
method has been recovered. Never call these regions with fake Windows
stack state or claim a game-code run based on opcode counts alone.

Priority A: Extend Win64 x64 static recompilation for 32-bit GPR
operations, EAX/ECX/EDX/R8D zero-extension, 32-bit memory accesses
and width-specific arithmetic/flags. The source changes now live in
native-port/recompiler/x64_function_aot.py, with cross-ISA reference
tests under native-port/recompiler/tests/test_x64_arm64_aot.py.
Success requires execution equivalence on both real x86 and
cross-compiled AArch64 test machine code, not just C++ syntax.

Priority B: Parse RUNTIME_FUNCTION and chained UNWIND_INFO to reject
epilogue-only or chained fragments, reconstruct a meaningful
function-level call graph and derive real complete function
boundaries instead of random short code ranges.

Priority C: Recreate original PE image read-only memory layout and
RIP-relative relocation, with explicit bounds and relocations;
do not falsely treat Windows source RVAs as Android pointers.

Priority D: Resolve external calls / function dependencies and
required Unity/Windows runtime services without inventing imported
functions or silently skipping calls.

Priority E: Add SIMD/XMM and remaining instruction widths, driven
by real opcode frequency and x86-vs-native test vectors.

Priority F: Run one *identified genuine CarX machine-code function*
on Android ARM64/Bionic with controlled real input and comparable
reference output. Only that can close the original game-code G0 gate;
no original CarX gameplay code has executed yet.

## Safety of project inputs and truthful scope

The uploaded ZIP stays outside the public GitHub repository.
No game executable, disassembly, code fragment or translated output
is committed. The only generated shareable report is opcode-frequency
and limitation counts, not the user's original copyrighted bytes.
The 170 requested cross-architecture test vectors still use
original test-only synthetic Windows ABI functions, not actual
CarX game semantics. Any test failure must be fixed before marking
that new coverage as passed. This is static compiler development,
not a playable CarX Android APK.
