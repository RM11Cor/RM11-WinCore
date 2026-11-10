# FH5 M26 — Verified shader metadata (original user-supplied evidence)

## Evidence / status

Analysis of user-provided `FH5_M26_GLOBAL_SHADER_EVIDENCE.zip`, not a claim of full shader execution.

- Outer asset: `Forza Horizon 5/media/_library/Shaders.zip` (120,167,930 bytes uncompressed as nested ZIP; 118,457,239 compressed within outer game ZIP).
- Extracted inner ZIP SHA-256: `f63adaf172e828059ac3b2416b9dbae800d52b1f05406f30a28cbe33cd416452`.
- Inner entries: 10,189; related candidate paths: 160; saved authentic `.shaderbin` samples: 8 (34,524 bytes total).
- Independently verified each saved sample SHA-256 against the extraction report.
- Each sample contains Grub `burG` version 257 and 9 non-overlapping blocks with FOURCCs `SRAV ECSL SLBD PMBC PMXT PMPS RPFD SREV TGRT`.
- Each sample contains 9 scenario-name strings including `CarLightScenario`, `CarLOD15LightScenario`, `CarShadowDepthLightScenario`, `SimpleCarLightScenario`, `WheelBlurScenario`, `ProxyLODLightScenario`, `CarRTBufferLightScenario`, `CarRayTracingLightScenario`, and `CarDebugLightingLightScenario`.
- 5 deliberately damaged variants rejected by independent format/hash validator.

## M10 original material -> M26 matched shader files

| materialbin | matching pg_trafficvehicles shaderbin |
|---|---|
| Clear_Glass, colour_glass, dark_glass | traffic_vehicle_glass |
| detail_diffAlphaGlossNorm | detail_diffalphaglossnorm |
| detail_diffalphamaskgloss | detail_diffalphamaskgloss |
| MultiSwatch | multiswatch |
| MultiSwatch_Emissive | multiswatch_emissive |
| trafficCarpaint | traffic_vehicle_paint |

**All 8 original materials match 6 distinct correct shader paths** (case normalized).

**Variant safety:** A second `traffic_vehicle_glass.shaderbin` under `trafficvehicle/` is DIFFERENT (4156 bytes vs 4056 bytes for `pg_trafficvehicles/`). M10 materials reference the `pg_trafficvehicles` one. `traffic_vehicle_paint_pbc` is an extra family member, not a replacement for M10's `traffic_vehicle_paint`.

## Release gate: do not overclaim

These shaderbin samples supply metadata and references, **not the actual extracted DXIL stage executables**. The original inner archive has compiled `.pcdxil.pso/.vso` variants; these bytes were NOT saved in the evidence ZIP. No `DXIL` or `DXBC` magic was found in the 8 saved shaderbin files. Do not claim:
- recovered source HLSL, exact paint/glass PBR semantics, or parameter bindings;
- equivalence of the two different glass variants;
- FH5 game executable, playable port, or production-quality shader translation.

## Next action

For M27 inspect the actual matching `CarLightScenario.pcdxil.pso` and `.vso` for `pg_trafficvehicles/traffic_vehicle_paint` and `pg_trafficvehicles/traffic_vehicle_glass`, capture individual file hashes, and examine DXIL/container/reflection. Limit download to four specific compiled files. The prior M26 global probe used a temporary file for the nested archive, which was deleted, and the compressed outer archive may require re-transferring ~118 MB; inform the user before any repeat download.

User's M23/M24/M25 stable APK builds remain untouched; this branch is evidence-only.
