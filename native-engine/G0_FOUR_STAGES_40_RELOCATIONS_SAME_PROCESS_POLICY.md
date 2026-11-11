# KERNIX G0 — approved four-stage integration plan, 40 original GNU relocations per stage

**Branch:** `kernix-native-engine-v1`  
**Policy status:** APPROVED TEST DESIGN, **not** a runtime success.  
**Existing evidence:** 147/147 independently certified *individual* ELF source writers; 8/147 independently attested inside one real Linux ARM64 FEX process (G0-L3, Actions #43074639291). Successful parallel 20/20 isolated FEX regression (Actions #43078736764) does not change the 8/147 same-process result.

## First Stage A SHA-pinned preflight verified (2026-11-11)

**GitHub Actions #43081973549: SUCCESS.** The actual GNU original
source indices `0..39` have been independently re-decoded against the
immutable original libc/ldso SHA and canonical 147 individual writer
ledger. The precise source type distribution is **3 R_X86_64_64**, **22
R_X86_64_GLOB_DAT**, **15 R_X86_64_TPOFF64**, allocated across **10
four-target hardware watchpoint windows**. The resulting verified plan
artifact is `KERNIX-G0-L40-A-Original-GNU-RELA0-39-40-Typed-Sources-10-Windows-NOT-Native-Proof`.

This is a **passed static source preflight**. It does not prove any of
the forty executed *together* inside a live FEX inferior. The stage's
runtime and independent hardware proof gate is explicitly **OPEN**.
Its mixed TLS/GLOB_DAT/absolute relocation set requires type-specific
native store, addend, signed TLS offsets, real loader resolution and
same-PID rearming validation. Never assume identical `stlr` register
patterns for every original relocation type.

## Four strictly isolated integration stages

| Stage | Original canonical relocation source indices | Targets | Separate real FEX process |
|---|---|---:|---|
| G0-L40-A | 0..39 | 40 | Yes |
| G0-L40-B | 40..79 | 40 | Yes |
| G0-L40-C | 80..119 | 40 | Yes |
| G0-L40-D | 120..146 | 27 | Yes |
| **Total** | **0..146, disjoint** | **147** | **4 separate stage runs** |

Stage ranges must be derived from the genuine SHA-pinned GNU ELF relocation table, preserving original `DT_RELA` versus `DT_JMPREL` kind, ordinal, type, signed addends, symbol binding/version/interposition, original destination, expected value or verified legitimate zero outcome. **Never invent targets** to fill a count.

Each stage starts **one** fresh FEX inferior process with unique PID, fresh memory, source hashes, and raw logs; it does not share an executing process, watchpoint, or outcome with another stage.

### Inside each stage — individual diagnostics without running each target serially as a separate test

- Preflight source metadata / already certified individual writer receipts **in parallel**. No need to rebuild FEX for every relocation.
- Observe up to **four hardware GDB watchpoints simultaneously**, then rearm at a *stopped checkpoint* before advancing the **same** process. The 40-target stages therefore need up to ten sequential 4-target observation windows (last stage up to seven), **not 40 simultaneous hardware watchpoints**.
- For each original source index, write a distinct immutable record: source SHA, table/index/type/symbol/addend, expected-vs-observed before/after qword, native FEX guest/JIT/ARM64 instruction and CPU register provenance, real inferior PID, watchpoint window, chronology, source branch and diagnostic error.
- The stage can be **certified only if all its expected targets actually execute and are independently verified in its same real FEX inferior**. A pass of a subset must be reported as partial. If one target faults or prevents further execution, retain all earlier authentic evidence, identify the failing index and why, and mark unobserved downstream entries **not tested**, never successful.
- If the faulty source prevents the rest of that one guest process from progressing, run **isolated diagnostic replay(s)** or narrower single-process chunks to locate the failure while preserving successes. Such replays **do not** fill gaps in the originally claimed forty-target same-process proof.
- Support `R_X86_64_GLOB_DAT`, `R_X86_64_64` (signed addend), `R_X86_64_TPOFF64` (signed TLS offset) and IFUNC/JUMP_SLOT using **their distinct true semantics**; e.g. original source index 63 TLS `stlr x4,[x10]` must not be rejected merely for not matching a GLOB_DAT `stlr x13,[x4]` template. Undefined loader symbols and symbol-version/preemption need actual resolver evidence. Deferred `JUMP_SLOT` under lazy binding is not automatically a FEX bug merely because it did not execute before process stop.
- Native SHA and independent evidence audit (with falsified-event negative controls) must pass separately for every stage; the output is a per-index PASS/FAIL/UNOBSERVED map, no blanket claims.
- Build FEX **once** where possible, share immutable binaries for the separate stages, and allow independent *preflight / fault-isolation* cases to run concurrently. Stage checkpoints run in the intended causal ELF relocation order; aggressive concurrency may not alter the true execution of a single loader process.

## What a four-stage pass means — and what it does not

All **four independent stage passes** establish each stage's set of native original relocation writers **within that particular stage's FEX process**. They **do not automatically establish all 147 target relocations in a single FEX process**, because the four stages use four different processes. A final **whole-process dynamic loader closure gate** still needs direct proof including all applicable relocations and actual lazy-binding behavior, `RELR`, loader self-relocations, IFUNC, TLS, symbol visibility, memory permissions/RELRO, correct libc initialization and process survival.

On-device Android/Bionic/Wine/Proton, games, Vulkan/Turnip/DXVK/VKD3D and measured FPS are subsequent **separate release gates**.

## Fail-closed progress reporting

Maintain independent counters:

1. `original_individual_native_writer_sources_certified=147/147` (already achieved).
2. `largest_independently_attested_same_process_original_source_window=8/147` (as of this policy).
3. `stage_{A,B,C,D}_same_process_passed_source_count`, each based **only on that stage's native evidence**.
4. `full_147_original_relocations_same_guest_loader_closure_proven=false` until an actual final end-to-end independent audit passes.

The prior 20/20 matrix cannot be credited as 20 same-process targets or be added arithmetically to 8. Preserve older proven L1-L3 receipts. **Do not rush or fabricate the stage counts; index-level fault isolation is more important than headline totals.**
