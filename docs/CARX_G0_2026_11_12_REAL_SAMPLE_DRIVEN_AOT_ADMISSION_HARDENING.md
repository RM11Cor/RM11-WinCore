# CarX G0 — true original Windows sample-driven AOT admission gate

Date: 2026-11-12. Branch carx-street-pc-port-v1.
Original private GameAssembly x86 source snippets never added to GitHub.

## Owner-provided original source facts

The user's previously exported PortLab v1.0 GameAssembly code ZIP
contained 256 actual PE RUNTIME_FUNCTION code regions, 33,153 bytes
of original machine code, with all 256 source SHA256 hashes matching.
The original Windows x86-64 GameAssembly.dll is 142,049,792 bytes.

The nine earlier coarse source-only candidates that had RET and no
obvious external imports were independently reviewed with GNU
objdump. Each is epilogue-oriented and none is proven an
independently callable original Unity IL2CPP gameplay function:

- RVA 0x40c438: 512-byte stack restoration, several nonvolatile POPs, RET.
- RVA 0x42c24f: saved register restoration, stack teardown and RET.
- RVA 0x4bf2e3: field writes followed by saved-register stack teardown.
- RVA 0x126d706: 32-byte stack restore, POP, RET.
- RVA 0x14c2178: 32-byte stack restore, POP, RET.
- RVA 0x17a29c4: return-byte write, 88-byte frame teardown, RET.
- RVA 0x1904926: 32-byte stack restore, POP, RET.
- RVA 0x2a37eff: zero result, 32-byte stack teardown, POP, RET.
- RVA 0x319a338: restores saved nonvolatile registers, frame teardown.

These conclusions concern only code structure, not CarX actual gameplay
function identity. The owner never provided full executable or Unity
source code to the public GitHub repository.

## Actual new source changes

1. win64_callable_source_gate.py combines source RVA/length,
   independently decoded Win64 UNWIND_INFO records, CHAININFO
   parent dependencies, exception handler dependencies, source
   prologue, stack budget and reachable CFG into one fail-closed gate.

2. analyze_carx_win64_xdata_zip.py now reports actual merged
   unwind+CFG source admission per function when an owner v1.1
   source package is supplied.

3. screen_carx_pdata_zip.py now enforces the v1.1 admission
   before emitting C++. A chained .pdata cold fragment cannot
   masquerade as a complete CarX gameplay method.

4. x64_control_flow_gate.py detects simple original PE epilogue
   fragments: when ADD RSP or POP removes source stack bytes
   before matching local SUB RSP or PUSH, that linear code region
   is not a stand-alone Win64 call entry. It does not mistake
   a matching SUB/ADD stack pair as an unmatched epilogue.

5. Synthetic tests exercise original unwind parent dependencies,
   RIP-relative original memory, unresolved external calls,
   missing RET, invalid source RVA, over-budget stack, and
   epilogue-only regions versus valid balanced source function.

## Proven test scope and next real input

The previous synthetic x86-reference vs compiled AArch64 test suite
achieved 330/330 output matches. A separate Android NDK workflow
previously built a real Android/Bionic AArch64 ELF64 shared library
from synthetic x86 bytes. Neither proves execution of original CarX
gameplay code, actual Unity scene, physics, or first rendered frame.

The still-missing owner v1.1 ZIP:
CarX_GameAssembly_AOT_Unwind_v1.1.zip

Only this new xdata/chain package can confirm actual original
CarX unwind parent relationships on-device. Reusing or resending
the v1.0 archive cannot answer that question.

Next G0 gate requires verified whole original GameAssembly source
method, original data/call dependencies, matching x86-reference
versus ARM64 method behavior, and then Android Bionic device test.
No additional general asset-inspector APK required.
