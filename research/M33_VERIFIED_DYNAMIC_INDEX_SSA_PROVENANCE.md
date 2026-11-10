# FH5 Native Port — M33 verified bounded SSA-index dependency tracing

## Sources and scope

- Four **user-supplied, original M27 DXIL compiled stage samples**: `pg_trafficvehicles/traffic_vehicle_{glass,paint}` CarLightScenario Pixel and Vertex shaders.
- Exact M27 file SHA-256 values re-verified before parsing; malformed/missing/duplicate files rejected.
- M28–M32 parser components reused; a new read-only M33 parser follows **bounded backwards SSA references** through known LLVM bitcode instruction records `BINOP`, `CAST`, and `EXTRACTVAL`. Calls and as-yet-unparsed control-flow operators are intentionally treated as **opaque origins**.
- No original shader bytecode or Forza game assets are committed to GitHub.

## Verified counts from compiled instructions

| Stage | Dynamic Constant Buffer row-read call sites | Dynamic `createHandle` resource index sites | First unresolved sources reached |
|---|---:|---:|---|
| Glass Pixel | 4 | **4** | All 4 row-index traces terminate at `dx.op.bufferLoad.i32` results; all **4 descriptor-index traces reach LLVM `PHI`** |
| Paint Pixel | 4 | 0 | All 4 row-index traces reach `dx.op.bufferLoad.i32` results |
| Glass Vertex | 30 | 0 | 20 row-index traces reach `dx.op.cbufferLoadLegacy.i32` results, 10 reach `dx.op.bufferLoad.f32` results; 8 traces also encounter `VSELECT` |
| Paint Vertex | 30 | 0 | Same 20/10 dependency split; 8 traces also encounter `VSELECT` |
| **Total** | **68** | **4** | **18/18 original-evidence regression and negative tests passed** |

**M31/M32 consistency:** 2,240 static DXIL `CALL` records, 104 `dx.op.createHandle` sites and 384 `dx.op.cbufferLoadLegacy` sites revalidated. M32 found 20 texture-operation call sites using dynamically selected glass SRV handles; those 20 uses reuse **4** dynamic handle creation results. Four handle definitions should **not** be confused with 20 subsequent operations.

## Guardrails and engineering conclusions

- **No runtime bounds are proven** for any of these 68 dynamic row indices or 4 dynamic SRV indices. The four glass SRV arrays lie in `space6:t0[*]`, an **unbounded descriptor range**, but the actual bound data/selected texture is still unknown.
- `PHI` and `VSELECT` are **opaque stops** in this limited M33 analysis; a dependency trace is **not** full program slicing or symbolic execution.
- `dx.op.bufferLoad` and `dx.op.cbufferLoadLegacy` results used in index calculations are not interpreted as original HLSL member values.
- Therefore no original paint/glass property names, reflection/refraction equations, final texture identities, or Vulkan-equivalent shaders are claimed.
- **M23–M25 Android viewer branches remain unchanged**; M33 is static shader research, not an APK build or playable FH5 port.

## Verification

- 18 Python checks passed: census, 4/4 original files and hashes, stage-specific counts, `PHI` origin check, register space/class, call-dependency types, 300-node / 30-level tracing bounds, no-render/no-proof flags, rejection of tampered/missing/duplicated/empty ZIP samples.
- Private downloadable `FH5_M33_DXIL_SSA_Index_Analyzer.zip` includes M28–M33 Python parsers, test script, JSON + Markdown metadata-only reports and Arabic instructions. The ZIP contains **no original shader binaries**.
- Independent container/session test: **18 tests ran; OK**.

## Next gate M34

Implement and **independently test** LLVM `PHI` and `VSELECT` operand decoding, inspect comparison/selection guards of the dynamic glass SRV index, and trace known runtime array bounds if present. Do not assume that simply knowing an SRV range is enough to prove safe runtime indexing.

## Technical format references

- [LLVM bitcode function record opcodes](https://codebrowser.dev/llvm/llvm/include/llvm/Bitcode/LLVMBitCodes.h.html)
- [Microsoft DXIL specification](https://github.com/microsoft/DirectXShaderCompiler/blob/main/docs/DXIL.rst)
