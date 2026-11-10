# FH5 Native Port — M32 verified DXIL texture/sampler operand map

## Evidence and provenance
Original source: four compiled M27 user-supplied DXIL stage files for `traffic_vehicle_paint` and `traffic_vehicle_glass`, in `CarLightScenario`. Each stage SHA-256 checked against the M27 manifest before analysis. Reused the verified M28–M31 metadata and LLVM relative SSA value numbering. **No original shader bytes or game assets are committed.**

## Exact static resource operand results

| Stage | M32 texture/buffer operations with resolved SRV (and sampler when applicable) | Dynamic CBV row loads | Operations on unbounded SRV ranges |
|---|---:|---:|---:|
| Glass PS | **89** | **4** | **24** |
| Glass VS | **31** | **30** | **24** |
| Paint PS | **39** | **4** | **4** |
| Paint VS | **32** | **30** | **24** |
| **Total** | **191/191** | **68** | **76** |

All 191 tested `sample*`, `textureGather*`, `textureLoad`, and `bufferLoad` call sites resolve to a real SRV handle emitted by `dx.op.createHandle`. Every filtering/sample/gather call also resolves a real sampler handle. Each operation's actual DXIL opcode matches the reference signature. The 2240 CALL / 104 createHandle / 384 CBV load counts were independently cross-checked against M31.

**IMPORTANT:** An unbounded SRV range is not a texture filename or a fixed texture ID; 20 operation sites use an explicitly dynamic descriptor index.

### Proven glass PS comparison resource bindings

- `dx.op.textureGatherCmp.f32`: **16** static call sites, `space6:t0[*]` (unbounded SRV array), paired with `space0:s9`.
- `dx.op.sampleCmpLevelZero.f32`: **4** static call sites, same `space6:t0[*]` unbounded resource range, paired with `space0:s10`.

This is genuine resource-operand provenance: **not** a demonstrated transparency/refraction algorithm, nor a verified texture identity. The actual `[*]` index values are computed by the shader at runtime.

### Dynamic constant-buffer row sources

- 68 of 384 `dx.op.cbufferLoadLegacy` call sites use a non-constant row index.
- Immediate SSA producers of **all 68** are LLVM `BINOP` instruction records (`FUNC_CODE_INST_BINOP = 2`).
- Breakdown: Glass PS b3=4, Paint PS b3=4; each Vertex Shader b2=20, b5=2, b6=8.
- The byte offsets, maximum runtime indices, original HLSL variable/member names and any connection to specific PBR material properties remain **unproven**. Producer BINOP classification is not a full expression tree.

### Register-index safety finding

The observed constant `createHandle` descriptor index in this compiled sample uses absolute source register numbers (for example range t116 has index=116), **not necessarily an offset of zero within the range**. The M32 validator checks against each declared register interval and does not incorrectly add the range start a second time. Dynamic indices cannot be proven within bounds by this static audit.

## QA and product limits

- **26/26 tests passed**, including 14 synthetic unit checks and 12 real-evidence integration assertions: exact stage counts, 191 operand-to-handle joins, 68 dynamic rows, 20 dynamic descriptor operation sites, verified glass s9/s10 wiring, SHA tamper and duplicate ZIP rejection.
- Private downloadable `FH5_M32_DXIL_Texture_And_CBV_Analyzer.zip` contains M28–M32 Python source, tests, JSON+Markdown metadata-only reports and Arabic readme. Original DXIL/game files deliberately omitted.
- M23–M25 stable Vulkan Android APK builds remain untouched. **No new APK at M32.**
- M33 gate: SSA backward dependency tracing of dynamic rows and unbounded texture indices to identify valid bounds and their data sources before inferring any property names or Vulkan material behavior.
- This is shader static analysis; it is **not** a playable Forza Horizon 5 port or a translation of the compiled DXIL into SPIR-V.

## Upstream technical reference
- [Microsoft DirectXShaderCompiler DXIL specification](https://github.com/microsoft/DirectXShaderCompiler/blob/main/docs/DXIL.rst)
- [LLVM Bitcode instruction format](https://llvm.org/docs/BitCodeFormat.html)
