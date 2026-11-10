# KERNIX G0 — original GNU libc IFUNC112 RET hardware-read checkpoint (2026-11-10)

**Branch:** `kernix-native-engine-v1`. **Accounting gate:** 27 independently proven distinct original libc relocation writers out of 147; a RETURN trace for the already counted IFUNC112 cannot increment this number.

## Completed and independently checked
- Genuine source SHA256-pinned unmodified Linux x86-64 GNU ELF guest triad:
  - `libc.so.6` `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`
  - `ld-linux-x86-64.so.2` `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`
- Source IFUNC112 DT_JMPREL / R_X86_64_IRELATIVE index `112`, table index `26`, resolver guest RIP `0x8040b15d0`, destination `0x804202cf0`, original source qword `0x282c0`.
- Source-locked real ARM64 FEX **hardware writer** independently certified in [run 42743772315](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42743772315) (27/147). This is a WRITE proof, not a RET/stack-READ proof.
- Bounded original GNU x86 disassembly [run 42743828657](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42743828657) found nine `c3` RET **source candidates only**:
  `0x8040b1628`, `0x8040b1661`, `0x8040b1690`, `0x8040b16a4`, `0x8040b16c0`, `0x8040b16e0`, `0x8040b17bf`, `0x8040b1ab8`, `0x8040b1d9b`.
- Dynamic native GDB CALL→resolver→C3 RET→stack hardware READ→GNU WRITE **source preflight** succeeded in [run 42747295232](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747295232). The candidate is intentionally selected *by actual JIT execution*, not by choosing an address in advance. Native result pointer comes from the separate hardware-writer proof rather than an invented constant.
- Earlier preflight [run 42747140902](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747140902) failed closed on an incorrect copied index 111; the index, target, and nine-source checks were corrected before the passing source gate.

## Launched; not yet certified at checkpoint creation
- [Actual Linux ARM64 one-FEX-process hardware READ experiment 42747579485](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747579485). The added original IFUNC112 trial uses the exact source-preflight plan and uploads real GDB hardware log and exit code.
- [Independent strict replay 42747923948](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747923948), including ten deliberate corruption rejections and cross-source IFUNC111 log rejection. It must fail closed if the authentic runtime is not successful, if its exit code is nonzero, or if stack/RET/store provenance differs.

## Acceptance / release boundaries
To close IFUNC112 full-return evidence, require **one genuine original FEX Linux ARM64 process** with a real CALL, native JIT resolver entry, selected source x86 C3 RET, the actual AArch64 hardware stack READ at guest slot `0x80300f9b8`, post-RET caller resumption, original GNU source native hardware `stlr x4, [x19]` to `0x804202cf0`, and strict independent replay. The new proof adds **zero** new unique writers to 27/147.

The 147 original libc relocations are **not** closed; G0/G1 remain open. This does **not** certify Android/Bionic 16KiB memory, Wine/Proton, GPU/Vulkan, APK release, Windows games, or FPS. Continue source-led, independently attested steps without substituting an earlier component or a fabricated runtime signal.


## Corrected live native trial and strictly pinned retry

The first actual ARM64 experiment [42747579485](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747579485) **failed closed before invoking the new IFUNC112 GDB**. The downloaded immutable source and writer checks passed, but a copied IFUNC111 pre-run assertion required `len(original_source_RET_guest_RIP_candidates)==3`; IFUNC112 has **nine**. This was an instrumentation assertion mismatch, not a verified FEX/C3-RET execution defect. The earlier dependent independent run [42747923948](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42747923948) also failed closed because the upstream trial had not succeeded.

The scoped fix changes the original **IFUNC112-only** live workflow requirement to `len(...)=9`, and changes its message from three/26 to nine/27. The passing IFUNC111 three-source test remains unchanged. Follow-up genuine ARM64 trial: [42748382102](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42748382102). Corresponding strict independent replay now pins *only* that corrected trial: [42748422303](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42748422303).

**Do not mark IFUNC112 native CALL→C3 RET→stack READ→GNU store as independently proven until these runs complete successfully and strict provenance/negative controls pass. Keep the unique writer ledger at 27/147.**

## Independently certified original IFUNC112 full-return closeout (2026-11-10)

The corrected genuine Linux ARM64 FEX source-pinned hardware execution [#42748382102](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42748382102) **passed**. The first independent replay [#42748422303](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42748422303) parsed the live GDB chain and passed all ten negative controls, but correctly stopped on an erroneous metadata constant copied from IFUNC111: its newly emitted `native_source_original_IFUNC112_distinct_writer_ledger_count` field was `26` while the separate certified IFUNC112 real writer was already the **27th**. The metadata-only fix commit [49b188b3](https://github.com/RM11Cor/RM11-WinCore/commit/49b188b3e534ef449894211a43eab50e4b4b2503) changed **26→27**, without altering real FEX evidence or counting a new relocation.

**Final independent authentic source and native-hardware proof [#42753565278](https://github.com/RM11Cor/RM11-WinCore/actions/runs/42753565278) succeeded.** For original IFUNC112, the pipeline attested one actual FEX ARM64 process with GNU x86 CALL, source JIT resolver, dynamically chosen original x86 `C3 RET`, guest stack native hardware READ, post-RET return to GNU caller, and original GNU hardware store to the source relocation target, tied to unmodified source ELF SHA and ten deliberately corrupted log rejections. The previous distinct target ledger stays at **27/147**; a successful full-return validation proves an already counted target's control flow and adds **0** new writers.

**Still OPEN:** 120 other original libc relocations, complete all-ELF relocation closure, real Android/Bionic 16KiB compatibility, graphics, Wine/Proton, APK release, actual Windows games and FPS. These remain gated independently; no compatibility or device success claim follows from this Linux source/hardware test.
