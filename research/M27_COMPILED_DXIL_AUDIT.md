# M27 verified compiled DXIL stage audit

Evidence source: user-uploaded FH5_M27_DXIL_EVIDENCE.zip. **Only metadata and hashes are recorded here; proprietary game binaries are not committed.**

## Verified result: 4/4 genuine compiled stages

| Shader | Stage | Container bytes | DXIL bitcode bytes | ISG1 inputs | OSG1 outputs | SHA-256 |
|---|---|---:|---:|---:|---:|---|
| traffic_vehicle_paint | PS 6.0 | 29249 | 24980 | 24 | 1 | 59785c737bca62235b01d686353552e1c7323e2c4fc8453cb99f2d2c7b2ea8b7 |
| traffic_vehicle_paint | VS 6.0 | 22680 | 18408 | 8 | 23 | 93582e73668f97435f78a3ea13345edaa05a2c49a00e9be7fcfea8023f48d076 |
| traffic_vehicle_glass | PS 6.0 | 31297 | 26884 | 24 | 2 | fe72b5b12d68a3530e6ea07fc0ada73047df65bf2969a02fed1e084fa5e4a2d7 |
| traffic_vehicle_glass | VS 6.0 | 21492 | 17364 | 7 | 23 | 5b25c4a826ccfd207547deb0b1b8f5cc21e8952f942e3302a94a4798d4e9ace9 |

Each DXBC outer container has exactly eight ordered parts: SFI0, ISG1, OSG1, PSV0, RTS0, ILDN, HASH, DXIL. DXIL contains real `BC c0 de` LLVM-family bitcode. Container lengths, chunk offsets and header bounds validated.

## Verified resource interface

The four RTS0 chunks are **byte-identical**. Their root signature has:
- 1.1 signature version; 12 root parameters, **all descriptor tables**; 34 ranges; 0 static samplers; flags 13.
- 22 SRV descriptor ranges (five unbounded), 9 CBV ranges, 2 sampler ranges and 1 UAV range.
- Five unbounded SRV ranges in register spaces 5, 6, 7, 8, 9.

These describe resource interface *capacity*, not which shader uses each resource or what an FH5 material parameter means.

## Verification and limitations

- Original M27 extraction report listed 4/4, and independent SHA-256 checks matched each payload.
- Six independent malformed-container variants rejected by standalone Python structural validator, stored privately in the conversation under `FH5_M27_DXIL_Auditor.py`.
- General-purpose Clang IR parsing was tried and failed with `Invalid ABI alignment, i8 must be naturally aligned`; an LLVM version or DXIL dialect incompatibility, not a demonstrated bad source archive.
- No HLSL decompilation, per-resource bindings or correct PBR material simulation has been proven.
- DXIL is not Vulkan SPIR-V; a source-compatible translation or separately implemented renderer is needed.
- M23–M25 stable viewer versions were not modified.

## Next gate M28

Parse PSV0 resource signatures + root descriptor table mapping, validate declared signatures; assess DXIL-aware tooling for IR introspection. **No binaries are embedded** in this repository and no claims of playable FH5.
