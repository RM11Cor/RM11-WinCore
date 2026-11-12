# CarX G0: actual original GameAssembly x64 function sample triage

Date: 2026-11-12. Source: owner-uploaded
CarX_GameAssembly_AOT_SourceFunctions_v1.0.zip, exported in PortLab v1.0
via Android SAF from the owner's extracted CarX Street PC folder.

This report shares aggregate analysis only. No original proprietary x64
function code, original GameAssembly.dll or copied game assets are committed
to this public repository.

## Authentic original Windows x64 source

- Source GameAssembly.dll length: 142,049,792 bytes.
- .pdata / IMAGE_DIRECTORY_ENTRY_EXCEPTION RUNTIME_FUNCTION entries: 412,001.
- Small (<321-byte) file-backed executable regions deemed export eligible:
  341,700 (subject to the original extractor's boundary heuristics).
- Deterministically sampled original regions: 256, total x64 code bytes: 33,153.
- SHA256 of all 256 source code slices individually matches the ZIP manifest.
- The owner ZIP SHA256 is
  6bbde5cfaaaccb27ea12cda1be31ee0afc6975e49d019a9650d58355a7dc68d8.
- Local binary disassembly used GNU objdump on the owner's bounded sample
  snippets. Counts below are per sample, NOT absolute instructions and
  NOT a proof of executable CarX method identities.

## First observed real instruction families and blocker frequencies

| Feature in the original sample | regions of 256 |
|---|---:|
| Direct call target beyond bounded region | 238 |
| RIP-relative memory references | 134 |
| SIMD/vector opcodes (disassembly heuristic) | 80 |
| Return instruction observed | 144 |
| No return observed | 112 |
| Direct jump beyond bounded region | 38 |
| INT3 padding/trap instruction | 82 |
| No external calls/jumps/RIP memory/vector/INT3 and has RET | 9 |

Major mnemonic occurrence by number of regions:
CALL 238, MOV 236, SUB 194, ADD 177, JNE 172, LEA 171,
POP 159, CMP 153, RET 144, XOR 136, TEST 133, PUSH 131,
JE 97, MOVUPS 60, MOVAPS 39, MOVSD 29, MOVZX 27,
XORPS 17, INC 17, NOP 17.

## Critical actual-code observation

Manual decode of all 9 apparently small local-RET source candidates
revealed that they are **mostly function epilogues / return sequences**,
sometimes setting a small result register and frequently restoring
saved registers and stack frames. Typical behaviors: ADD RSP,
POP nonvolatile register(s), RET. This is consistent with original
Win64 exception/pdata covering unwind/chained subregions, and
demonstrates why a syntactically self-contained slice is not
automatically an independent entry-point or game function.

The current prototype AOT emitted correct AArch64 instructions for
**eight synthetic Windows ABI test functions**, with 80/80 observed
cross-ISA equivalence in GitHub CI; that proof remains valid for
the tested subset, but **no original CarX method has yet executed**.

## Engineering direction supported by actual source

G0.A: Read Win64 .pdata plus unwind metadata to identify genuine
function entry points and distinguish chained regions or epilogues.
The next sampling criteria must exclude probable epilogues and
record image relative addresses and callers.

G0.B: Support 32-bit and 8-bit register/memory writes, ABI-correct
zero extension/flags, and RIP-relative addressing for PC source
references. Calls need a bounded interfunction symbol map before
being interpreted, including IL2CPP Unity runtime imports.

G0.C: Implement x86 SIMD SSE2 scalar/vector semantics or a verified
mapping where actual source code uses them. Never silently substitute
ARM64 NEON operations with different rounding/flag behavior.

G0.D: Pick one **whole, actual IL2CPP method** through metadata
code registration / caller graph with a controllable interface,
translate it statically and execute it on ARM64 with a verified
reference output. A translated return-sequence fragment is NOT G0.

The Android Vulkan synthetic GPU clear/readback proof is separate.
A user-supplied ZIP of code samples, metadata header or a successful
APK build is NOT the original CarX game scene/physics/first frame.
Do not repeat generic diagnostic APKs; use original instruction
requirements to prioritize only necessary recompiler changes.

Local script for reproducing source-only structural triage:
native-port/recompiler/triage_real_pe_functions.py

CI must use synthetic machine-code snippets only, never owner DLL
or copyright-derived code.

## Source privacy

The user supplied a sample ZIP privately in this conversation.
Keep the original ZIP, generated game-derived C++, or any proprietary
binaries out of public GitHub commits and public release artifacts.
All raw source remains local to the owner/workspace.
