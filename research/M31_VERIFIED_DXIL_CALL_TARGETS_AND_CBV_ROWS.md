# FH5 Native Port — M31 verified DXIL CALL target and CBV row provenance

## Source and integrity
- Four original CarLightScenario shader binaries from **user-supplied M27 evidence ZIP**. Each stage fingerprint is checked against the M27 reference before parsing.
- Static LLVM v1 relative-value ID reconstruction: module function declarations + constants + per-instruction SSA results; type table determines void-returning calls. Resolves each `FUNC_CODE_INST_CALL = 34` to its *actual* module symbol.
- No shader bytecode, proprietary textures or game executables included in GitHub.
- M23–M25 Android viewers and the M30 branch are unchanged.

## Fully decoded CALL targets, verified with real stages

| Stage | All CALL targets | createHandle -> metadata resource | cbufferLoadLegacy -> known CBV |
|---|---:|---:|---:|
| Paint Pixel Shader | 633 | 33 | 93 |
| Glass Pixel Shader | 677 | 41 | 115 |
| Paint Vertex Shader | 481 | 16 | 90 |
| Glass Vertex Shader | 449 | 14 | 86 |
| **Total** | **2240/2240** | **104/104** | **384/384** |

Each `dx.op.createHandle` is linked to the **actual class and range ID** from M29's `dx.resources`; each `dx.op.cbufferLoadLegacy` is linked to the returned CBV handle, its original `b` register and row argument. All calls are static instruction sites, not measured runtime execution counts.

## Pixel material CBV `space0:b0` — directly observed rows

| Shader | Declared CBV size (M29) | CALL sites | Unique constant rows |
|---|---:|---:|---|
| Paint PS | 64 B | 5 | **0, 1, 2, 3** |
| Glass PS | 24 B | 4 | **0, 1** |

A row is indexed in 16-byte units; the 24-byte glass buffer occupies two 16-byte row positions, with partial trailing data. **Do not infer** original HLSL member names or a paint-color vector solely from these rows.

Other CBVs have **dynamic row indices** at multiple call sites, so static constant row sets are not exhaustive.

## Newly proven use (not merely symbol presence)

- Glass Pixel Shader contains **16 actual calls** to `dx.op.textureGatherCmp.f32`.
- Glass Pixel Shader contains **4 actual calls** to `dx.op.sampleCmpLevelZero.f32`.
- Paint Pixel Shader does **not** call those two functions in this sampled compiled permutation. The visual consequence is **not yet proven**.

## Safety and reproducibility

- All **14 independent unit tests passed**, including malformed call flags, wrong function type, invalid target ID, unknown resource range, corrupted handle operand, unsupported LLVM opcode, module-version mismatch, and original file hash mismatch.
- Metadata-only source and JSON/Markdown reports packaged privately as `FH5_M31_DXIL_Call_Provenance_Tools.zip` (27 KB).
- The package includes prior M28–M30 Python parser dependencies so it can rerun with a **user-provided M27 evidence ZIP**. Original shaders are never included in the package.
- Reconstructing LLVM call sites does not produce HLSL, translate DXIL to SPIR-V, or run the ForzaTech engine.

## M32 next gate
Trace **dynamic row-index SSA dependencies** and the register/space of texture/sampler calls; identify candidate property evidence *only if* actual DXIL instructions and material files corroborate it. Hold on new APK builds until the renderer has a verifiable visual change.

## References
- [LLVM Bitcode: relative value IDs](https://llvm.org/docs/BitCodeFormat.html)
- [Microsoft DXIL specification: createHandle and CBufferLoadLegacy](https://github.com/microsoft/DirectXShaderCompiler/blob/main/docs/DXIL.rst)
