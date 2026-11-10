# FH5 M30 — Verified LLVM DXIL function-call census

## Evidence and safety

This research stage read four user-supplied M27 compiled shader files, verifying their **SHA-256** fingerprints against the M27 reference before processing. It uses a bounded custom LLVM 3.7-era **bitstream record parser** to enumerate FUNCTION_BLOCK records and VALUE_SYMTAB symbol names. **No proprietary game shader bytes** are included in this repository or report. The M23–M25 stable Android renderer branches are unchanged.

## Static instruction record results

| Shader / CarLightScenario stage | Function instruction records (excluding DECLAREBLOCKS) | CALL records | Declared dx.op symbols |
|---|---:|---:|---:|
| traffic_vehicle_paint — Pixel | 2,729 | **633** | 17 |
| traffic_vehicle_glass — Pixel | 2,889 | **677** | 20 |
| traffic_vehicle_paint — Vertex | 1,708 | **481** | 13 |
| traffic_vehicle_glass — Vertex | 1,595 | **449** | 13 |
| **Total** | **8,921** | **2,240** | — |

**CALL code=34** is the LLVM bitcode function instruction record (`FUNC_CODE_INST_CALL`). These are **static records**, NOT per-frame runtime GPU execution counts, and they do not establish the identity of the actual call target without SSA value-ID resolution.

### Actual embedded symbol declarations

- Both pixel shader blobs have `dx.op.createHandle`, `dx.op.cbufferLoadLegacy.f32`, `dx.op.cbufferLoadLegacy.i32`, `dx.op.sample.f32` and `dx.op.textureLoad.f32` in their module value symbol tables.
- The glass Pixel Shader declares `dx.op.sampleCmpLevelZero.f32` and `dx.op.textureGatherCmp.f32`, absent from the paint Pixel Shader declaration set.
- The paint Pixel Shader declares `dx.op.textureGather.f32`, absent from the glass Pixel Shader declaration set.
- Actual original shader entrypoint names recovered from the value symbol tables:
  - paint PS: `LightScenarioMainPS`
  - glass PS: `ColorGlassLightScenarioMainPS`
  - paint VS and glass VS: `VS3D`

**Important:** A symbol in a module means it is declared, **NOT yet proven called** by a specific instruction. Calling these declaration differences confirmed transparency or reflection operations would be unsound.

## Validation performed

- All 4 original SHA-256 fingerprints match M27;
- Parsed one shader function body per stage with bounded subblock/abbreviation/record parsing;
- **15/15 independent local tests passed**, checking four stage signatures, entrypoint/function counts, static call totals, feature flags and malformed/tampered/truncated/duplicated samples;
- A self-contained private downloadable metadata-only ZIP includes `m30_instruction_audit.py`, its M29/M28 parser dependencies, tests, JSON + Markdown reports and per-file SHA-256 manifest. No source shader bytes are redistributed.

## Explicit remaining gates

1. Decode SSA value numbering and function call targets in DXIL bitcode to distinguish actual `createHandle`, `cbufferLoadLegacy` and `sample` calls.
2. Trace constant buffer row indices and dependencies to identify actual `b0` member usage. M29 only established overall CBV **byte lengths**.
3. Verify material semantics from real use sites before considering any Vulkan shading translation. DXIL is not native Vulkan SPIR-V.
4. No original HLSL source, physical glass/paint formulas or playable Forza Horizon 5 port have been produced.

## Sources for format interpretation

- [LLVM `FUNC_CODE_INST_CALL = 34`](https://llvm.org/doxygen/LLVMBitCodes_8h_source.html)
- [Microsoft DXIL specification](https://github.com/microsoft/DirectXShaderCompiler/blob/main/docs/DXIL.rst)
