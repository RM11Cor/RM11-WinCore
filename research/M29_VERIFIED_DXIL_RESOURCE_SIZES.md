# M29 — Verified FH5 DXIL `dx.resources` metadata analysis

## Evidence and method

- Source: four original compiled DXIL shaders in the user-supplied `FH5_M27_DXIL_EVIDENCE.zip` (two `traffic_vehicle_paint` and two `traffic_vehicle_glass` CarLightScenario stages), matched against exact M27 SHA-256 fingerprints.
- Built a **read-only, independent LLVM 3.7-era bitstream record parser** to inspect `dx.resources` named metadata, resolve metadata references and integer constant values, and correlate each resource register with the independently parsed M28 PSV0 declaration.
- Source repository report contains **only metadata**, no original shader binaries, source code, proprietary textures or full game assets.

## Confirmed result

| Stage | SRVs | CBVs | Samplers | UAVs | Matching declared resources | Populated HLSL names |
|---|---:|---:|---:|---:|---:|---:|
| traffic_vehicle_paint.pso (pixel) | 20 | 6 | 7 | 0 | 33/33 | 0 |
| traffic_vehicle_paint.vso (vertex) | 5 | 8 | 2 | 0 | 15/15 | 0 |
| traffic_vehicle_glass.pso (pixel) | 23 | 6 | 8 | 0 | 37/37 | 0 |
| traffic_vehicle_glass.vso (vertex) | 4 | 8 | 1 | 0 | 13/13 | 0 |
| **Total** | **52** | **28** | **18** | **0** | **98/98** | **0/98** |

All 98 original DXIL `dx.resources` metadata records match the PSV0 `(class, register space, lower bound, upper bound)` multiset exactly. Four metadata entries use unbounded descriptor ranges (`-1` encoded in DXIL metadata, PSV0 upper bound `0xffffffff`).

**Notable negative finding:** All **98/98 source resource-name fields are empty** inside these four compiled shaders; no original HLSL texture/sampler/constant buffer names can be recovered from those particular fields. Do not invent names or use PSV0 labels as HLSL names.

## Constant buffer sizes from actual `dx.resources` metadata

These are declared **whole-CBV byte lengths**, not internal struct-member offsets, PBR parameters or shader register interpretation beyond the binding.

| Shader | CBV binding → size in bytes |
|---|---|
| Paint PS | b0=64, b2=6796, b3=18376, b4=996, b9=384, b11=56 |
| Glass PS | b0=24, b2=6796, b3=18376, b4=996, b9=384, b11=56 |
| Paint VS | b1=140, b2=6796, b3=18176, b4=996, b5=208, b6=49152, b9=384, b11=56 |
| Glass VS | b1=140, b2=6796, b3=18176, b4=996, b5=208, b6=49152, b9=384, b11=56 |

All these CBV bindings use register space 0. The distinct Pixel Shader `b0` length is **64 bytes in paint vs 24 bytes in glass**. Both Vertex Shader CBV binding/size lists match.

## Validation

- **18 local unit checks succeeded**, including binding count and PSV cross-checks, buffer sizes, bitcode truncation/magic rejection, malformed resource counts and register mismatches, duplicate metadata-name rejection, and original file fingerprint checks.
- Parser resolves signed LLVM constant encoding, `METADATA_NAME`/named-node references, `METADATA_VALUE` references and `METADATA_NODE` lists; it rejects unexpected layouts and does not execute shader binaries.
- Companion local artifact: `FH5_M29_DXIL_Resource_Audit_Tools.zip` (Python parsers, tests, JSON and Markdown report). The artifact intentionally omits proprietary shader binaries.

## Limits and next gate

- Constant buffer *lengths* are now grounded, but individual **CBV member names, offsets and types are still unknown**. Resource names are absent in these four samples; original HLSL source and paint/glass lighting equations were not recovered.
- M30 should analyze type annotations and actual DXIL instruction references / `dx.op.createHandle` and `dx.op.cbufferLoadLegacy` call sites with a DXIL-aware bitcode tool. Only infer material behavior if supported by concrete metadata or instruction evidence.
- This does not mean DXIL can run directly on Vulkan, nor that Forza Horizon 5 game logic was ported. M23–M25 stable Vulkan viewer APK branches remain untouched.

### Format references
- [Microsoft DirectXShaderCompiler DXIL specification](https://github.com/microsoft/DirectXShaderCompiler/blob/main/docs/DXIL.rst)
- [DXIL resource metadata record layout](https://github.com/microsoft/DirectXShaderCompiler/blob/main/include/dxc/DXIL/DxilMetadataHelper.h)
- [LLVM bitcode block and abbreviation format](https://llvm.org/docs/BitCodeFormat.html)
