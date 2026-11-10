# FH5 Native Port — M28 verified DXIL PSV0 resource bindings

**Evidence:** four user-supplied M27 `pg_trafficvehicles` compiled stages; each source SHA-256 rechecked. No original game shader bytes are published to GitHub.

## Main result

| CarLightScenario stage | CBV | Sampler | Typed SRV | Structured SRV | Total |
|---|---:|---:|---:|---:|---:|
| traffic_vehicle_paint.pso | 6 | 7 | 17 | 3 | 33 |
| traffic_vehicle_glass.pso | 6 | 8 | 18 | 5 | 37 |
| traffic_vehicle_paint.vso | 8 | 2 | 5 | 0 | 15 |
| traffic_vehicle_glass.vso | 8 | 1 | 4 | 0 | 13 |

All **98/98 stage resource records** are covered by compatible register ranges in the byte-identical RTS0 root signature (12 root descriptor tables, 34 ranges). Covered means the register/space/class fall within the declared root descriptor range; it **does not** imply that every resource is read by active shader instructions.

## Paint vs glass pixel shader: distinct bindings

- 29 identical descriptors shared.
- **8 glass-only:** SRV StructuredBuffer t108, t109; Texture2D t115, t116; TextureCube t117, t118; sampler s9, s10 (space 0).
- **4 paint-only:** Texture2D t19, t38, t51; sampler s11 (space 0).
- The glass-only resources are **not automatically proven** to implement reflections, transparency or refraction. They are just stage declarations.

## Paint vs glass vertex shader

- 13 common declarations.
- **2 paint-only:** TextureCube t118 and sampler s1 (space 0).
- No glass-only vertex resource declarations.

## Stage interface consistency

- For **each** paint and glass pipeline, **23 vertex output signature elements** match corresponding pixel shader input elements, matching semantic kinds/names and indices.
- Each pixel shader has one extra system-generated `IsFrontFace` input from rasterization.
- Pixel output signatures are **one** `SV_Target` element for paint and **two** for glass. This alone does not prove transparency/dual-pass semantics.

## Verification

- 4 exact stage file SHA-256 checks, 98 descriptor-to-root cover checks, 2 VS/PS semantic joins.
- 23 local regression checks succeeded, including **18 malformed-input rejection tests** (header/stride/type/signature/root table/changed shader SHA-256).
- Custom PSV0 resource and PSVSignatureElement parser follows Microsoft's `DxilPipelineStateValidation.h` structure and D3D12 version 1.1 root descriptor range layout.
- Local, metadata-only audit reports available privately with `FH5_M28_PSV_Resource_Audit_Tools.zip`.

## Limitations and next engineering gate

- This phase is **static reflection/validation only**. No decompiled HLSL, original lighting equations, material parameter names, or DXIL-on-Vulkan support are claimed.
- To reach material fidelity, M29 must decode DXIL's `dx.resources` metadata with DXIL-aware tooling (or inspect matching symbol/reflection data), resolving actual resource names and constant-buffer layouts before deciding any Vulkan parameter mappings.
- M23–M25 viewer APKs are left unchanged; no new APK is needed for a metadata-only step.
