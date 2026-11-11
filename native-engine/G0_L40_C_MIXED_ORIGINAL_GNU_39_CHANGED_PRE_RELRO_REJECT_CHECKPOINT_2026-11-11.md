# KERNIX G0-L40-C — real GNU mixed PLT/IFUNC source-what-changed checkpoint

**Date:** 2026-11-11. **Branch:** `kernix-native-engine-v1`.  
**Status:** stage C mixed original source native-writer integration **NOT independently complete**.

## Previously completed

- Stage A original GNU DT_RELA source0..39: **40/40 real Linux ARM64 FEX hardware writer events inside one host inferior**, independently attested in Actions **#43085088606**, 60 forged event controls rejected.
- Stage B source40..79: **40/40 real Linux ARM64 FEX hardware writer events inside another host inferior** (PID 2813), independently attested in Actions **#43091554154**, 60 forged event controls rejected, source44 isolated AWATCH and signed TPOFF64 source63 handled explicitly.
- Those are **two distinct same-process windows, not 80 original relocations in ONE process**. The separate original 147/147 individual target writer certification is older and does not imply loader completion.

## G0-L40-C original GNU source and native diagnosis

- SHA-pinned original GNU original libc/ldso source C preflight **#43092287024 SUCCESS**: original source indices **80..119** are **5 `R_X86_64_GLOB_DAT`**, **16 `R_X86_64_JUMP_SLOT`**, and **19 `R_X86_64_IRELATIVE`** (first six from `DT_RELA`, remaining 34 from `DT_JMPREL`). Original PLT source qwords are **nonzero**; do not assume all source values start at 0.
- Initial attempt to snapshot AFTER `ExecuteThread`, **#43092776770 FAILURE**, correctly preserved the raw log: host inferior PID 2785 exited code 177 octal because original GNU guest attempted another `mprotect` for a non-main RELRO page. Failing to reach host ExecuteThread return is **not** proof of missing source stores and must not be treated as loader success.
- Actual Linux ARM64 FEX pre-rejection snapshot **#43093873518 SUCCESS**, PID **2846**, independently attested **#43094785120 SUCCESS** with **24 forged source/PID/event log rejections**:
  - All 40 original source qwords were read BEFORE the actual source relocation phase.
  - At the source-authentic main RELRO policy-reject boundary, exactly **39/40 source qword values differed from their original source ELF qwords**, indices 80..84 and 86..119.
  - Index **85** is an original `R_X86_64_IRELATIVE` with initial qword **zero** and was still **zero** at the snapshot. This could be a legitimate zero result, an unchanged slot, or no store: **it does not prove actual resolver invocation or zero-to-zero write**.
  - Both read-only checkpoints were hit in one real FEX host Linux ARM64 PID 2846. **No direct native hardware write instruction** for the 39 changes was independently attested by that read-only snapshot.
  - `JUMP_SLOT` lazy vs eager binding and original `IRELATIVE` function entry/return correctness remain unproven. No full GNU loader result from this snapshot.

## Actual GNU ld-linux versus main RELRO ownership blocker

The source-authentic host recorded:

```text
KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT request=801036000 expected=800003000 relro_first=0 relro_end=0 source=0 owner=0 live=r--p
```

The actual immutable original GNU ELF64 `PT_GNU_RELRO` program headers show:

| Original ELF source | Source PT_GNU_RELRO | Real FEX guest page span |
|---|---|---|
| `bin/kernix-g2e-dynamic-guest` | `p_vaddr=0x3db8`, `p_memsz=0x248` | `0x800003000..0x800004000` (one 4KiB page) |
| `lib64/ld-linux-x86-64.so.2` | `p_vaddr=0x36360`, `p_memsz=0x1ca0` | `0x801036000..0x801038000` (two 4KiB pages) |

The *observed* request address `0x801036000` points to the original **ld-linux self-RELRO**, not the original **main ELF RELRO**. The original host's **main** RELRO audit correctly rejected an address it had not established as an owned **main** page; code must **never disable or weaken the source/VMA/protection checks to push through to a false success**.

The existing host includes a distinct source-verified **ld-linux self RELRO 8KiB** path, but that path requires other prior original source state such as main ELF RELRO already sealed; direct progression/order and ownership must be verified by the real x86 guest and source original loader. A source-program-header classifier is being tested separately; **source ownership alone never authorizes mprotect**.

## Next controlled live tests

1. Native ARM64 FEX same-inferior hardware watches on the first four C original `GLOB_DAT` source indices **80..83** via the new real source script and workflow `kernix-g0-l40-c-first-four-true-original-globdat-one-fex-native-arm64.yml`. That workflow **must succeed with independent native writer audit** before any source index is newly claimed inside this stage.
2. Verify the true original `IRELATIVE[85]` resolver source entry and return, including whether a zero-to-zero slot store occurred. Do not use a simple GDB write-only watchpoint as proof of zero-to-zero.
3. Diagnose `DT_JMPREL` eager/lazy original PLT binding individually in one true process. Keep distinct original relocation type and per-index provenance.
4. Preserve exact original GNU main/ldso `PT_GNU_RELRO` page ownership and only apply real guest mprotect after correct kernel VMA, source opcode and relocation-closure gates.

**All four-stage native relocation integration and full GNU interpreter / Android/Bionic/Wine/Proton game launch remain OPEN.**
