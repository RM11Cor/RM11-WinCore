# M36 — Conditional descriptor capacity gate for FH5 original glass DXIL

## Authenticated primary evidence

- Read-only analysis of the exact **user-supplied M27 DXIL four-stage archive** (original SHA-256 manifests checked through the M28–M35 chain).
- Checked against the user's **M25 material audit report** (eight materials, including three glass materials). All three named glass materials reference `pg_trafficvehicles/traffic_vehicle_glass/traffic_vehicle_glass.shaderbin`, matching the compiled `CarLightScenario` family studied here.
- This repository document contains **no copyrighted shader binary or game asset data**. All numbers below come from our local evidence checks; they are not a GPU runtime trace.

## New CFG/dominator proof

The M35 report already established two bounded-loop conditions with **runtime-supplied**, not static, integer bounds from `space0:b2 row71`.

M36 independently computes the original glass shader control-flow graph's dominators and **natural loops**. The exact `dx.op.createHandle` SSA definitions used for the four dynamic glass texture indices belong to their expected loop bodies, and the entry header dominates each handle block.

| Original induction PHI | Header / latch BB | Natural-loop blocks | Handle SSA → BB | Dynamic image descriptor formulas |
|---|---|---:|---|---|
| `phi708` | 19 / 35 | 17 | 782 → BB21; 935 → BB29 | `phi708 + 10` and `phi708 + 11` |
| `phi1015` | 40 / 54 | 15 | 1089 → BB42; 1205 → BB48 | `phi1015 + 30` and `phi1015 + 31` |

For the shader's original signed comparisons and **nonnegative, immutable runtime bounds** `N1,N2` within the safe no-overflow range:

- First loop, if `N1 > 0`: highest index is `N1 + 10`; requires **`N1 + 11`** accessible descriptor slots (index 0–N1+10). If `N1=0`, its two analyzed dynamic handles are not reached.
- Second loop, if `N2 > 0`: highest index is `N2 + 30`; requires **`N2 + 31`** slots. If `N2=0`, its two analyzed handles are not reached.
- For the **four dynamic handles only**, the conditional shared-range capacity check is:

```text
required_capacity =
    max((N1 + 11 if N1 > 0 else 0),
        (N2 + 31 if N2 > 0 else 0))
capacity >= required_capacity
```

This is a **conditional sufficient upper bound on the four individual handle indices**; it is **not** a proof that every descriptor access of the full shader pipeline is safe. The analysis restricts `N1 ≤ 2,147,483,637` and `N2 ≤ 2,147,483,617` to avoid signed 32-bit image-index arithmetic overflow, and requires nonnegative `N` and actual populated descriptors at indices 0..required−1.

**Illustrative numbers only, not FH5 measurements:** `N1=4,N2=2` requires `max(15,33)=33` slots for the four handles. Capacity 33 passes the *conditional* arithmetic gate; 32 fails it.

## Data availability: explicit blocker

- Original runtime bounds are **unknown**: `N1` = CBV `space0:b2 row71 component1`, `N2` = same row component2.
- The M25 parsed material audit **does not report** these CPU-uploaded uniform values or the number of GPU descriptors bound in `space6:t0[*]`.
- M25 shows **zero direct swatch references** for those three glass material entries, but that is NOT evidence that global textures are absent; the descriptor array can be populated elsewhere.
- Thus `runtime_observation_available=false`, `unconditional_runtime_safety_proven=false`, and `full_shader_descriptor_safety_proven=false`. Do not infer texture identities or actual game render capacity from this report.

## Verification and distribution

- **26/26 new M36 tests passed**: original sample hash chain, M25 glass material linkage, two natural loops, four dominated handle blocks, exact index formulas, exhaustive small-value simulator cross-check (`N1,N2=0..15`), 150 seeded randomized cases, capacity just below threshold, zero-loop cases, i32 overflow/negative/bad-input rejection, mutated M25 source rejection, damaged SSA-bound metadata rejection.
- **70/70 M33–M35 regression tests** passed, all from user-owned evidence plus synthetic malformed cases. **96/96 tests passed overall**.
- `FH5_M36_Descriptor_Capacity_Audit_Tools.zip` contains **20 source/test/JSON/Markdown/checksum files**, zero original shader binaries, modelbin, materialbin, textures or APK. Local archive SHA-256: `e4ade9eebcd51b8c95404e8c993d998a8242d600842cad983a41e3fbc40f6202`.
- The standalone sample capacity calculator under `tools/FH5_M36_Conditional_Capacity_Calculator.py` is only a conditional mathematical diagnostic. It **does not** read the Android GPU or capture the FH5 runtime.

## M37 release gate

A runtime observation containing verified `b2` row71 components 1 and 2 **and** the populated `space6:t0` descriptor count from the *same render state* is needed to evaluate this conditional gate against real FH5 resource bindings. A successful gate would still need independent tests for other pipeline descriptor accesses and actual shader translation. No new APK is justified by M36 alone; M25 Vulkan viewer remains unchanged.

**No playable FH5 port, original HLSL recovery, full PBR material reproduction or safe original Vulkan reimplementation is claimed.**
