# KERNIX device diagnostics — one upgradeable Android package contract

## Decision: no more one-icon-per-opcode tests

User has confirmed old C3-D3..C3-D8C6 / G1 / G0 independent
diagnostic APKs may be uninstalled after their on-device evidence was
recorded. Those APKs served bounded acceptance gates; they were **not**
the stable emulator.

Starting with the next **functional, Linux-ARM64-proven** Android
runtime gate, new phone tests should be delivered through a single
long-lived application ID, proposed:

\`org.kernix.diagnostics\` (separate from stable KERNIX's package).

- One launcher icon: **KERNIX Diagnostics**. No additional app icons
  for each G0 ld-linux subtest or graphics frame count.
- Initial install once; subsequent signed APKs use the **same**
  package/application ID, identical original verified signing
  certificate, and **monotonically incremented versionCode** so
  Android's ordinary APK installer updates in place.
- The program must **not claim** cloud/automatic background updates.
  Installation of a newer APK is a user-controlled action.
- Primary display = **latest actionable diagnostic stage**;
  prior completed stages may be displayed as **historical read-only
  evidence**, NOT re-run without regression justification.
- Latest stage's native child is paired with an immutable, source
  witnessed SHA256 manifest; exact Linux guest ELF files and FEX
  library digests verified before execution. No runtime downloads,
  network or arbitrary EXE selection.
- One opt-in button, watchdog timeout, captured capped output,
  output marker-order validation, clear error/status, no root, no
  shared-storage modification, no persistent child processes, and
  explicit "NOT Linux full loader/NOT Wine/NOT games" on probes.
- Continue using **one original source-verified FEX + the pre-existing
  C3-D7B/C3-D7G host-owned guest memory model**. Avoid parallel
  implementations.
- On host 16K page devices, deny unsafe 4K guest page assumptions
  unless independent software subpage protection is actually proven.
- Existing KERNIX v0.27 stable application, installed game folders
  and prefixes remain untouched. Never use the stable package ID as
  diagnostic target or attempt in-place downgrade.
- Each device PASS requires a user-submitted actual Android process
  screenshot / export and an immutable build/run/source evidence JSON
  in \`native-engine/evidence/\`. A green GitHub Action/Android APK
  build does NOT count as execution on the phone.

## Existing bounded stages preserved (no repeat required)

1. Actual original FEX G0 x86 Linux \`pread64\` and genuine ldso
   header guest byte read: Android screen PASS.
2. Actual source-authentic FEX G0 x86 \`mmap\`, guest store/load, and
   \`munmap\`, native owner-held page release: Android screen PASS.
3. Original source SHA Linux ELF PT_LOAD + genuine AUXV + true FEX
   mmap/store/load/munmap in one native process: Android screen PASS.
4. Original \`ld-linux\` PT_INTERP first exact original source MOV
   instruction after guest heap syscalls in the same FEX context;
   source PT_LOAD bytes restored, bounded HLT: Android screen PASS.
5. Earlier G1 180-frame and Surface/Swapchain device probes are
   strictly bounded visual/presentation evidence; neither game
   renderer nor full Vulkan runtime was proved.

### Current unreleased integration gate

- **Linux ARM64:** original \`ld-linux\` source \`MOV\` plus source
  \`CALL rel32\` after real original FEX x86 heap guest syscalls
  in a *single* process, with correct native guarded host callret
  stack, guest return RIP, original target bounded HLT,
  W^X restoration, and all guest windows freed.
- Initial strict Clang constructor ordering fixed in
  \`d31e935894357f72fa97bd86033637e18d2a98b4\`.
- [CI #42097578226](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42097578226)
  compiled, but **segfaulted at actual execution**, NOT PASS. The
  original stderr artifact had no app-emitted stage marker before
  \`timeout\` reported a core dump.
- Source \`native-engine/android-host/tests/kernix_g0_original_elf_heap_then_ldso_mov_call_bounded_arm64.cpp\`
  now instruments exact phase markers without altering guest CPU
  state, source bytes, mmap policy or runtime logic.
- Live diagnostic CI:
  [#42156774041](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42156774041)
  started at the time this contract was authored. Its result must be
  inspected rather than guessed.
- **Do not publish yet another standalone diagnostic APK** or assign
  the new app package a fake runtime pass. First close the actual
  Linux ARM64 segfault at a verified narrow stage, then require
  Android/Bionic cross-link PASS, then prepare the unified
  updateable signed Android app.

## Definitive release acceptance checklist

The exact proposed \`org.kernix.diagnostics\` package may first ship
only after all conditions are proven in the same build pipeline:
(1) actual source-pinned original FEX Linux ARM64 functional PASS,
(2) original FEX Android/Bionic cross-link PASS,
(3) original source ELF and guest SHA256 witness match,
(4) original certificate signing and APK payload digest verification,
(5) versionCode strictly greater than previous diagnostics release
(or 1 on first install),
(6) all Java failure handling and native process isolation verified,
(7) release declares on-phone execution **PENDING**, never PASS.
User must then run exactly one specific test on their REDMAGIC
Android device and send its actual result.

Until (1) and (2) are proven, the latest archived signed APK remains
only a previously bounded diagnostic; a new APK would create
unnecessary clutter and false confidence.


## 2026-11-06 — first stable-package Diagnostics APK released and signed

**The Linux original-source FEX MOV+CALL-after-heap crash was resolved**:
CI [#42156774041](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42156774041)
identified a SIGSEGV after C3-D7G applied \`PROT_NONE\` but before
permission plan construction. Code fix \`3274bcfd10c968604b3fae69e86746e67e55bb2a\`
builds/verifies the source-original permission plan and genuine
\`PT_INTERP\` CALL target **before** hardening native page rights.
Corrected real FEX Linux ARM64 execution
[CI #42157283860](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42157283860)
**PASS**. Source-pinned Android/Bionic FEX native cross-link
[CI #42157777076](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42157777076)
**PASS**.

The one-app solution is implemented at
\`native-engine/android-unified-diagnostics-app\`, with
\`org.kernix.diagnostics\` as its permanent application ID. The
source-tree \`current-probe.json\` is disabled; only exact attested
release workflow enables the current diagnostic while bundling
correct SHA256-pinned ELF/FEX binaries and licensing notices.
Standalone compile-only [CI #42157857725](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42157857725)
PASS and deliberately did **not** publish a debug APK.

The separately signed original-certificate first release
[CI #42158236209](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42158236209)
**PASS**:

- Release tag: \`kernix-diagnostics-v1-g0-ldso-mov-call-e34fd3a8\`
- Signed APK: \`KERNIX-Diagnostics-G0-LDSO-MOV-CALL-Android-v1-Signed.apk\`
- Package: \`org.kernix.diagnostics\`
- versionCode: \`1\`; every future APK **must increment** versionCode
  and keep original signing certificate and same package.
- APK SHA256: \`d680f1b863dacd7db2f30a1a83595f6f6d0b5053daab82be5fa9cb3849a934a7\`
- Exact file size: 2,114,421 bytes
- GitHub direct file:
  https://github.com/RM11Cor/RM11-WinCore/releases/download/kernix-diagnostics-v1-g0-ldso-mov-call-e34fd3a8/KERNIX-Diagnostics-G0-LDSO-MOV-CALL-Android-v1-Signed.apk
- Machine evidence:
  \`evidence/kernix-diagnostics-v1-real-original-fex-x86-mov-call-after-heap-android-signed-phone-pending-20261106.json\`

**Physical device on-phone result for the NEW MOV+CALL integrated
test is PENDING**, despite Linux functional and Android cross-link
and APK signature successes. Ask for ONE user on-phone test via
\`KERNIX Diagnostics\` and exact output:
\`G0_ANDROID_SOURCE_LDSO_MOV_CALL_AFTER_HEAP_PASS=1\`,
\`EXIT_CODE=0\` and the six bounded ordered native markers.
No claim of full original dynamic ld-linux startup/glibc or PC games.

If successful, close the bounded combined MOV+CALL gate and move on
to a genuinely functional PT_INTERP loader/TLS/relocations integration,
not to opcode-count microtests. Continue to update this **same**
package (versionCode 2,3,...) instead of issuing new app IDs or
testing the previous completed stages again.


## 2026-11-06 physical Android acceptance: v1 original FEX ELF+heap+ld-linux MOV+CALL — CLOSED

User supplied the actual screenshot of the newly signed, first
**single permanent-package** \`org.kernix.diagnostics\` application
with every marker in expected order. Screen shows:

\`\`\`text
G0_ANDROID_SOURCE_LDSO_MOV_CALL_AFTER_HEAP_PASS=1
EXIT_CODE=0
FULL_LDSO_GLIBC_OR_WINE_GAME_PROVEN=0
\`\`\`

The runtime log additionally showed verified original SHA source,
native PT_LOAD W^X permissions, real x86 FEX guest ELF/AUXV reads,
true mmap(9)->guest store/load->munmap(11), genuine original
\`ld-linux\` PT_INTERP \`mov %rsp,%rdi; call rel32\`, guarded
FEX call-ret stack, original CALL target bounded-HLT stop, exact
source byte restoration, no full loader start, and child exit 0.

This evidence is **one user-screen-observed on-device PASS** — not a
hardware-attested trace. Canonical immutable record:
\`native-engine/evidence/kernix-diagnostics-v1-original-ldso-mov-call-after-guest-heap-physical-android-screen-pass-20261106.json\`.

This stage is now **closed; do not re-request it**. The stable
KERNIX v0.27, its Wine prefixes and local game files were not
modified. The next phone diagnostic must **update**
\`org.kernix.diagnostics\` using versionCode >=2 and the **same**
verified original KERNIX signing certificate. Do not create a
new application ID and do not publish standalone new test icons.

### Next real functional loader gate (not instruction counter)

- Integrate the verified original source-backed dynamic loader callee
  with the existing Android-phone-accepted **single original FEX**
  guest ELF/AUXV process and its guest Linux syscall ABI.
- Use existing validated C3-D7J/K/L original glibc TLS/FS models and
  original ldso staged source RX/RW policy as implementation references
  only. Their host reference validation or bounded opcode runs **do
  not prove actual source-original runtime TLS setup**.
- Aim for a *semantic* milestone: original ldso callee reaches its
  next authentic loader startup state using real guest stack and
  writable original-data PT_LOAD; source verified modified guest
  bytes and register/stack contract, no out-of-policy host syscall,
  no source file modification, W^X and guard preservation.
- A failure should yield the **first precise reason, stage and
  native signal / guest RIP** in a capped signed diagnostic log.
  Avoid treating "more x86 instructions queued" as functional
  progress.
- Gate next signed Diagnostics **v2** on source-pinned original FEX
  Linux ARM64 functional PASS, Android/Bionic native link PASS,
  original file and licensing SHA256, original KERNIX certificate and
  same package ID with greater Android \`versionCode\`. New
  Android execution is *PHONE PENDING* until user personally runs
  the updated app and submits screenshot.
- Full original \`ld-linux\` initialization, \`glibc\`,
  \`Wine\`/\`Proton\`, Windows PE execution and games remain **unproven**.

## Next bounded functional loader-state candidate — Linux validation gate (2026-11-06)

The closed signed Diagnostics v1 phone gate is **not** reopened. A new,
separate source candidate at
`native-engine/android-host/tests/kernix_g0_same_fex_original_ldso_rw_state_after_heap_arm64.cpp`
extends the same original FEX context beyond the old injected-HLT
CALL boundary. It attempts original source-authenticated callee bytes
with exact PT_INTERP/ELF/AUXV stack, genuine guest x86 mmap/store/load/
munmap, then native-original `ld-linux` prologue/stack/SIMD and a
source-derived writable loader data-byte AND plus RIP-relative LEA.
The test proves the RW side effect by temporarily seeding a single
bit in **owned anonymous guest memory**, checks the source-derived
result and 192-byte stack frame, and restores all staged guest bytes
under W^X. No source ELF bytes or user game files are edited.

CI workflow:
`.github/workflows/kernix-g0-original-ldso-rw-state-after-heap-arm64.yml`.
Initial source commit: `e8422419492a6626312733256671ebf6d47c4f9a`.
Workflow commit: `4303c48b07c5775023595986d298a48adde75a7b`.
Initial execution run:
https://github.com/RM11Cor/RM11-WinCore/actions/runs/42162571919

**This paragraph records an engineering candidate, not a test PASS.**
Until the same-process Linux ARM64 runtime step returns exit 0 and
its ordered heap, original ldso RW-state and restoration markers are
confirmed, this stage is **CI PENDING/UNVERIFIED**. Even if it passes,
it is a bounded instrumented source-callee side-effect proof, **not**
the completion of `ld-linux` or glibc relocation/TLS/IFUNC, Wine,
Proton, Windows PE, graphics, actual Android on-device execution, or
game compatibility. Only after functional Linux ARM64 PASS should
the independent Android/Bionic native linkage gate be attempted.
No signed Diagnostics v2, no new app ID, no new icon, and no impact
on the installed v1 or stable v0.27 until the release gates pass.

## 2026-11-06 G0 original ld-linux callee RW-state AFTER real guest heap — Linux ARM64 PASS

[**Real original FEX functional execution #42163385087**](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42163385087)
PASSED at commit `a65f2c38836b2afbe8dc594288092276f203f447`.
It is **not** a compile-only green: the signed source-authenticated
original x86 Linux ELF main/PT_INTERP/ld-linux/libc guest staging,
AUXV reads and real guest mmap/store/load/munmap ran in ONE FEXCore
host session before the original PT_INTERP MOV/CALL and the genuine
original ld-linux callee performed its own source-relative writable
PT_LOAD byte update and guest stack frame writes. The Linux job
required a real exit code zero, correctly ordered independent native
markers, and bit-sensitive source-derived guest RW effect.

The first attempt [#42162571919](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42162571919)
failed **after ExecuteThread returned**, because the new verifier
mistakenly expected the seventh saved guest stack word (guest RBX)
to be zero. Original GNU x86 assembly actually retains the
historical guest mmap return address in RBX *after* its corresponding
munmap. Fix `a65f2c38836b2afbe8dc594288092276f203f447` gates
that original source-owned historical address and diagnostic slots;
the next real Linux ARM64 run #42163385087 passed. This corrects a
test oracle, **not** an upstream FEX source translator bug.

Verified on Linux ARM64 ONLY: authentic ldso callee state,
source-relative RW side effect, saved guest registers and stack,
source byte restoration and native W^X protection in a
bounded instrumented session. A temporary HLT still stops the next
authentic callee instruction; glibc relocation, TLS, IFUNC and full
dynamic startup remain unverified.

Next **Android/Bionic native link-only** gate is introduced in
`.github/workflows/kernix-g0-original-ldso-rw-state-android-bionic-buildonly.yml`
(commit `240441a079baeef993d07701be07e634867b29bb`), referencing
actual Linux PASS #42163385087 and the SHA-locked, previously
successful source-built Android FEXCore #42157777076.
[Build-only CI #42163937029](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42163937029)
must be checked for final result, artifact hashes and ABI before
Android-device testing may even be considered. **PENDING/NOT YET
PROVEN** at documentation time. This workflow does not publish,
sign, install or execute an Android APK and does not change the
stable KERNIX v0.27 or the installed signed Diagnostics v1.

## 2026-11-06 KERNIX Diagnostics v2 official original-signed same-package release — PHONE PENDING

The successful real Linux ARM64 functional original-loader RW-state
gate [#42163385087](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42163385087)
was integrated with an Android/Bionic **compile-only** gate.
The first Android/Bionic CI [#42163937029](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42163937029)
failed solely because original FEX build-generated headers
`FEXCore/Config/ConfigValues.inl` and `ConfigOptions.inl`
were not generated by CMake configure alone.
Fix `877ed1ee82dd7e4c83b9bad68851ca2c2aafb80e`
explicitly builds upstream custom targets `CONFIG_INC` and
`IR_INC`. Real Android/Bionic arm64 cross-link and exact source ABI
then **PASSED** in [#42166430049](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42166430049).
This is **not Android physical device execution**.

The v2 signed release workflow was introduced at
`f772b18c3fc33488a29af71682f03e45c74c2845`.
Its first run [#42166877956](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42166877956)
rejected an obsolete v1-specific `compile-result.json` lookup;
fix `a9c17c9f4ee24948c23829f3d4bd3095c6385fdc`
correctly attests v2 `accepted-source.json` plus the exact Bionic
`android-candidate/candidate.json`, native runner and source SHA256.
The old v1 release and permanent app identity remain untouched.

The new official source-verified release pipeline
[**CI #42166956055 — SUCCESS**](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42166956055)
attested real Linux ARM64 original FEX loader RW-state execution and
Android/Bionic compilation; verified the actual Android native runner,
original FEXCore, pinned original guest triad, glibc LGPL and FEX license
notices, exact original KERNIX signing certificate, Android
`applicationId=org.kernix.diagnostics`, `versionCode=2`
(v1 was `versionCode=1`), manifest probe markers and APK ZIP CRCs.

- **Release tag**: `kernix-diagnostics-v2-g0-ldso-rw-state-a9c17c9f`
- **APK**: `KERNIX-Diagnostics-G0-LDSO-RW-STATE-Android-v2-Signed.apk`
- **Size**: 2,116,962 bytes
- **Published GitHub release asset SHA256**:
  `a1d4886fcef1015e73fae0a55541957773dd24a66c24b6026258fea00acf1988`
- **GitHub verified direct APK URL**:
  https://github.com/RM11Cor/RM11-WinCore/releases/download/kernix-diagnostics-v2-g0-ldso-rw-state-a9c17c9f/KERNIX-Diagnostics-G0-LDSO-RW-STATE-Android-v2-Signed.apk
- **Android phone pass key**:
  `G0_ANDROID_SOURCE_LDSO_RW_STATE_AFTER_HEAP_PASS=1`
- Required separate line: `EXIT_CODE=0`, plus ordered
  `KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_CALLEE_GUEST_RW_AND_STACK_STATE_VERIFIED`
  and
  `KERNIX_G0_SOURCE_CALLEE_GUEST_RW_STACK_AND_EXECUTABLE_RESTORED_WX_SAFE`.

**Phone status: PENDING** until a user-initiated physical Android
installation and execution supplies the actual in-app diagnostic
screenshot. CI/ABI/signed release does **not** establish Android runtime
loader semantics, full original ld-linux/glibc TLS, Wine/Proton, PE
execution, games or FPS. **Do not re-request already closed v1 MOV/CALL**
and do not release another separately named diagnostic app or touch
the installed stable KERNIX v0.27, Wine prefixes or game data.

## 2026-11-06 physical REDMAGIC Android Diagnostics v2 loader RW-state — USER SCREEN PASS, GATE CLOSED

User has now run the source-authenticated `org.kernix.diagnostics`
`versionCode=2` release on a physical Android handset and supplied a
visible in-app output screenshot. **The actual displayed result is:**

```text
G0_ANDROID_SOURCE_LDSO_RW_STATE_AFTER_HEAP_PASS=1
EXIT_CODE=0
FULL_LDSO_GLIBC_OR_WINE_GAME_PROVEN=0
```

The screenshot visibly contains ordered device-side stages for exact
original SHA256 source, guest ELF/AUXV/stack, native RX/RW/W^X,
original FEX CPUState, genuine x86 guest mmap/munmap, actual source
`ld-linux` callee writable data-byte effect and guest stack frame,
and original source/memory restoration. The decisive native result
lines include:

```text
KERNIX_G0_SAME_FEX_ORIGINAL_LDSO_CALLEE_GUEST_RW_AND_STACK_STATE_VERIFIED
KERNIX_G0_SOURCE_CALLEE_GUEST_RW_STACK_AND_EXECUTABLE_RESTORED_WX_SAFE
KERNIX_G0_SAME_FEX_LOADER_RW_STATE_ANDROID_CANDIDATE_NOT_FULL_LDSO
```

This closes the **bounded, integrated, real-FEX ELF/AUXV + guest
heap + original source loader RW/stack side-effect phone gate**.
It supersedes the *PHONE PENDING* status in the historical v2
release paragraph above. Screenshot evidence is user-observed,
not independent hardware attestation. Canonical audit record:
`native-engine/evidence/kernix-diagnostics-v2-original-ldso-rw-stack-after-heap-physical-android-user-screen-pass-20261106.json`
(commit `216d046a2036b9fe4fe16fe6e77132e70731898f`).
No screenshot binary is placed in public source control.

**Do not re-request v1 or v2 tests.** The next signed Diagnostics
update must remain `org.kernix.diagnostics`, original signing
certificate, and `versionCode>=3` only after independently
successful substantive functional Linux ARM64 real-FEX integration
and actual Android/Bionic linkage gates. Preserve installed v2,
the stable KERNIX v0.27, all prefixes and user games.

### Next phase: real dynamic loader dependency/relocation/TLS semantics (NOT YET PROVEN)

Prior separate host-only C3-D7I/J/K ELF dynamic/relocation,
glibc Variant II TLS and FEX FS/GS **preflight** models are useful
source-verified *dependencies*, not proof of execution. The
C3-D8C6 prior 28-instruction phone smoke test is also closed.
Stop increasing arbitrary instruction counts. The new gate must
demonstrate, in the SAME authentic FEX x86 process already proven
to reach original `ld-linux`:

1. A source-derived relocation target, actual guest relocation
   write and independent read-back under allowed RW pages, with
   collision/overflow/unknown relocation rejection.
2. Real x86 guest TCB/DTV and FS base materialization or an
   explicitly isolated earlier startup milestone with no false TLS
   completion claim; 47 IFUNC/IRELATIVE resolvers require actual
   resolver semantics before full-loader completion.
3. Real guest Linux syscall/signal handling, disallow unexpected
   host calls; exact guest RIP, stack, source ELF SHA, W^X,
   guarded mappings, cleanup and post-relocation RELRO.
4. Linux ARM64 real FEX execution PASS before independent Android
   Bionic native link PASS, then single signed same-package v3
   PHONE PENDING and only user-reported on-device proof changes it
   to PHONE PASS.

**No complete glibc/ld-linux, Wine/Proton, Windows PE, Vulkan,
DXVK/VKD3D or games have been demonstrated by v2.**
