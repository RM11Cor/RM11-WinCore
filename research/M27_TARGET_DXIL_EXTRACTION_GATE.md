# FH5 M27 — exact DXIL stage extraction gate

## Verified reference from M26 user evidence
- Main compressed outer entry: `Forza Horizon 5/media/_library/Shaders.zip`.
- Compressed bytes: **118,457,239** (`ZIP method=8` in the outer archive).
- Uncompressed inner ZIP bytes: **120,167,930**.
- Inner SHA-256: `f63adaf172e828059ac3b2416b9dbae800d52b1f05406f30a28cbe33cd416452`.
- 10,189 entries in the inner ZIP.
- M26 extracted only `.shaderbin` metadata, **NOT DXIL executables**.

## Four targeted native compiled shader assets

1. `pg_trafficvehicles/traffic_vehicle_paint/traffic_vehicle_paintCarLightScenario.pcdxil.pso` — pixel shader (expected by file-naming convention; verify presence)
2. `pg_trafficvehicles/traffic_vehicle_paint/traffic_vehicle_paintCarLightScenario.pcdxil.vso` — vertex shader (expected by file-naming convention; verify presence)
3. `pg_trafficvehicles/traffic_vehicle_glass/traffic_vehicle_glassCarLightScenario.pcdxil.pso` — pixel shader (M26 index: 31,297 bytes)
4. `pg_trafficvehicles/traffic_vehicle_glass/traffic_vehicle_glassCarLightScenario.pcdxil.vso` — vertex shader (M26 index: 21,492 bytes)

**Do not use** the separate `trafficvehicle/` glass variant or the ray-trace-lookup permutation as substitutions.

## Local extraction design

The accompanying user-facing M27 Python tool is provided privately in the ChatGPT conversation as `FH5_M27_DXIL_Extractor.py`, with a ZIP and Arabic guide. It:
- first checks for `/sdcard/Download/FH5_M27_Cache/Shaders.zip`;
- reuses it without network if byte length and SHA-256 match the M26 reference;
- otherwise downloads just the compressed outer `Shaders.zip` entry once, using remotezip and a bounded destination, then **retains** the verified archive for subsequent steps;
- finds four filenames by *exact case-insensitive match*, rejects duplicates, writes hashes, header diagnostics and bounded `DXBC` / `DXIL` container probes;
- writes `/sdcard/Download/FH5_M27_DXIL_EVIDENCE.zip`, never executes the code and never includes a whole game distribution.

## Validation performed

Synthetic compressed nested-ZIP selftests passed for exact four-file selection, CRC-backed reads, duplicate rejection, full-size container bounds checks and corrupt header rejection. **Live M27 original DXIL extraction is not yet proven**; user needs to run the tool on their game archive and return the evidence.

## Release gates

No claims about decompiled original HLSL, shader registers, PBR semantics, game logic or playable FH5 should be made from the filenames or a DXBC header alone. Publish no original game shader binaries in public GitHub history. Do not modify the M23–M25 stable viewer branches.
