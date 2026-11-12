# KERNIX-independent CarX x64 → native AArch64 static recompiler (G0)

## What exists

Unlike a PC gaming compatibility APK, this tool performs
**build-time static translation** of a bounded x86-64 function into
C++ and compiles that into genuine ARM64 machine code. No x86 decoder
or FEX/Wine service is included in the resultant native program.

Initial translator:
- native-port/recompiler/x64_function_aot.py
- Handles Windows x64 64-bit register arguments RCX, RDX, R8, R9.
- Handles 64-bit MOV, MOVABS, LEA, ADD, SUB, XOR, AND, OR, CMP,
  TEST, INC, DEC, local direct CALL and JMP, conditional branches,
  PUSH, POP, 64-bit stack-relative reads/writes and RET.
- Rejects unsupported SIMD/AVX, register widths, external imports,
  indirect branches, TLS, SEH, and Unity-specific engine calls
  *rather than emitting incorrect code*.
- Produces explicit C++ instruction semantics. The resulting ARM64
  code has a bounded guest register/memory/control-flow state, so it
  is an initial **function-level** recompiler, not a complete
  high-performance whole-program AOT optimizer.
- Guest instruction decoding happens once during build with Capstone.
  The emitted ARM64 runtime has **no x86 byte decoder**.

## Actual cross-architecture execution evidence

GitHub Actions #43214654515:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/43214654515

Eight distinct synthetic Windows ABI x86-64 machine-code functions
were assembled and executed on x86-64. The recompiler lifted exactly
those machine bytes to native C++, which was cross-compiled using
aarch64-linux-gnu-g++ and executed by a QEMU AArch64 runner *in CI
only*. For each, the output matched native x86-64 reference across
ten independent vectors: 80/80. The test runner is NOT a runtime
dependency on the phone or of the final ARM64 binary.

Tests also reject unsupported instructions, invalid/cut bytes,
indirect/external branch targets, missing return, and 32-bit
register writes until those are supported correctly.

**This proves recompiler functionality for the currently supported
x64 subset; it does not yet prove CarX code has been translated.**

## Real original CarX input bridge (PortLab v1.0)

Owner's original GameAssembly.dll is x86-64 Windows PE, ~142 MB,
in their game directory accessible via the Android Storage Access
Framework (SAF) but previously not accessible to Termux.

To avoid transferring 22GB or requiring Termux to see protected
files, PortLab v1.0 provides a user-initiated export:

1. Install the permanently signed v1.0 APK **over v0.9**, with no
   uninstall (same signing identity, versionCode 10).
2. Open the app. Existing SAF selected game-folder grant is reused.
   If not saved, choose the root CarX Street folder one time.
3. Press **استخراج دوال GameAssembly الحقيقية (AOT)**.
4. Android prompts where to save
   CarX_GameAssembly_AOT_SourceFunctions_v1.0.zip.
5. The app opens GameAssembly.dll *read-only*, parses its real
   IMAGE_DIRECTORY_ENTRY_EXCEPTION / RUNTIME_FUNCTION table, maps
   begin/end RVA boundaries into file-backed executable sections,
   and exports up to 256 deterministic sub-320-byte x86 functions.
   It includes per-function SHA-256 metadata and offsets.
6. Only the small ZIP is shared for analysis; source DLL and all
   game assets remain in place. The ZIP is NOT uploaded to GitHub
   by the app.

This is first contact with **real CarX GameAssembly function bytes**.
A Win64 RUNTIME_FUNCTION entry is not guaranteed to correspond to a
Unity IL2CPP method or gameplay function. We must evaluate the
instruction bodies themselves before identifying any functionality.

## Offline screening & native code generation from real original snippets

On a computer with Python 3.12+ and the Capstone dependency,
the next-stage script can be run against the user-owned ZIP:

    python -m pip install capstone==5.0.6
    python native-port/recompiler/screen_carx_pdata_zip.py \
      CarX_GameAssembly_AOT_SourceFunctions_v1.0.zip \
      --out carx-real-aot-candidate-results.json \
      --cpp-out-dir ./native-port/recompiler/local-generated-output

The script checks member names, SHA-256, bounded archive sizes,
correct relative RVA and original code. Supported functions get
generated C++; unsupported functions receive a *category* so
we can add only the missing opcodes required by the real game.

To compile supported code to real AArch64 Linux:
    aarch64-linux-gnu-g++ -static -O2 \
      local-generated-output/generated_XXXXXXXX.cpp \
      -o translated_function_aarch64

Then validate on AArch64 test runner against a controlled reference,
not by assuming that AArch64 code execution equals CarX gameplay.

**Do not commit original source snippets or generated proprietary
game-derived code to the public repository.** Keep the phone's
source ZIP and generated C++ in local workspaces.

## Important technical boundaries

- Win64 import calls, Unity IL2CPP runtime method registration,
  native player API and metadata type identity still need mappings.
- Real CarX graphics, physics and scene logic are not running yet.
- AOT guest-state dispatch is function-level and not yet optimized.
  The first goal is semantic equivalence for *actual* CarX functions.
- Current cross-platform CI validates AArch64 **Linux** generated
  machine code. A subsequent codegen step will target Android
  NDK/Bionic ARM64 and invoke JNI with actual device proof.
- No new generic Vulkan demo or extra asset inspector is required.
- The user-requested "no emulation on device" means x86 translation
  must complete at build time; QEMU is allowed for CI verification
  only and is not packaged into Android.
