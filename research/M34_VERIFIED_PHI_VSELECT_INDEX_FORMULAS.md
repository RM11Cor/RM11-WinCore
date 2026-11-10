# FH5 M34 — Verified PHI / VSELECT SSA provenance for dynamic texture indices

## Original evidence and branch isolation

Analysis uses only four original **user-supplied M27 compiled DXIL files**, revalidated against exact M27 SHA-256 fingerprints; no source game binaries are committed here. The work follows the bounded read-only M28–M33 parser design. Original M23–M25 working Android viewer branches and KERNIX are unchanged.

## What is genuinely new and established

The four dynamic `dx.op.createHandle` descriptor indices in **`traffic_vehicle_glassCarLightScenario.pcdxil.pso`** resolve to **two LLVM PHI loop induction variables**:

| DXIL createHandle result SSA | Index input SSA | Exact symbolic integer ADD expression | Shared induction PHI |
|---:|---:|---|---:|
| 782 | 781 | **phi708 + 10** | 708 |
| 935 | 934 | **phi708 + 11** | 708 |
| 1089 | 1088 | **phi1015 + 30** | 1015 |
| 1205 | 1204 | **phi1015 + 31** | 1015 |

For each PHI node, the incoming values were explicitly decoded from LLVM v1 **signed, sign-rotated relative SSA IDs**, including the forward-referenced backedge:

- `phi708`: predecessor **BB18 → literal 0**, predecessor **BB35 → SSA1005 = phi708 + 1**.
- `phi1015`: predecessor **BB39 → literal 0**, predecessor **BB54 → SSA1275 = phi1015 + 1**.
- Exactly **two** unique PHI source nodes across the **four** dynamic handles. All four handles access the original `space6` / `SRV` / `t0[*]` declared unbounded descriptor range.
- The additional offsets 10, 11, 30 and 31 are **compiled static arithmetic operands**, not known filenames, fixed resource IDs, or proven runtime bounds.

**These are induction patterns, not a termination proof**: no loop exit predicate, number of iterations, actual descriptor-array length or out-of-bounds behavior has been established.

### VSELECT decoder and vertex constant-buffer index paths

The new parser now follows both value alternatives **and** the condition operand of each observed compact LLVM v1 `VSELECT` (3 relative-value fields), instead of marking it as opaque as M33 did. In each vertex shader (paint and glass), there are **two distinct VSELECT nodes reached** from the 30 dynamic constant-buffer row-index traces. Comparisons with known compact shapes are also traced, but the actual branch/predicate outcome is **not** proven.

All **68 dynamic CBV row-read** sites from M33 are retained; all 72 tracked dynamic index sites (68 CBV + four SRV handle definitions) can be traced to supported or explicitly **opaque** leaves, with no node/depth-limit truncation. Calls, unknown branch conditions, and unhandled instructions remain opaque.

## Validation

- **26/26 new M34 tests passed**: exact original file hash, 2 PHIs, four formulas, 4 handles in space6, vertex VSELECT presence, signed-forward PHI decode, invalid PHI block/value layouts, malformed arithmetic, original ZIP tamper/missing-file rejection, explicit negative bound assertions.
- **18/18 M33 regression tests passed**. **44/44 overall**, run on original user-provided evidence plus synthetic negative cases.
- Original cross-stage totals remain 2,240 static CALL records, 104 createHandle sites, 384 CBV loads, and 68 dynamic row indices.
- Private source bundle `FH5_M34_PHI_VSELECT_DXIL_Analyzer.zip` contains source, tests and JSON/Markdown reports **without original DXIL/game assets**. SHA-256 of this package: `88f84ad128b809ae774c6551c62718c7594d1de8512664a0620fa6766a703cf7`.

## Explicit nonclaims and next gate

**No shader runtime bound, original HLSL reconstruction, selected texture identity, material PBR formula, Vulkan shader equivalence or playable FH5 port is proven here.**

Next M35 gate: reconstruct **basic-block control-flow** for BB18/35 and BB39/54; decode branch comparisons and any loop exits, then investigate whether a sound bound on the induction values can be established. Only if proven should a Vulkan material mapping or safe descriptor-array size be inferred.

### Public format references

- [LLVM Bitcode File Format — signed-vbr forward PHI SSA values](https://llvm.org/docs/BitCodeFormat.html)
- [LLVM BitcodeReader — sign-rotated PHI and VSELECT record decoding](https://github.com/llvm-mirror/llvm/blob/master/lib/Bitcode/Reader/BitcodeReader.cpp)
