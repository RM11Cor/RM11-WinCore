# FH5 M35 — Verified dynamic glass texture loop guards from original DXIL control flow

## Integrity and scope

- Source: four **user-provided original M27 compiled DXIL samples**, matched against the exact M27 stage SHA-256 fingerprints.
- M35 isolates the `traffic_vehicle_glass.pso` executable LLVM bitcode to decode `FUNC_CODE_INST_BR`, `FUNC_CODE_INST_CMP2`, `FUNC_CODE_INST_PHI`, `FUNC_CODE_INST_BINOP`, and `dx.op.cbufferLoadLegacy.i32` instruction provenance.
- **No proprietary shader binaries, game data or textures** are committed to this repository. The stable M23–M25 Android asset-viewer branches are untouched.
- The reader recovered **146 basic blocks**, **145 BR instructions**, **one RET**, and validated the exact CFG predecessor set of all **135 PHI nodes** in the glass Pixel Shader.

## Verified loop sources

Both M34 induction variables have a directly verified *symbolic runtime limit*, not a fixed numerical one. Both limits come from the same original **space0:b2 CBV, row 71** (16-byte row begins at byte offset 1136 in its 6796-byte declaration). The comparison input is an `i32` extracted component.

| Property | First original shader loop | Second original shader loop |
|---|---|---|
| Counter | SSA `phi708` | SSA `phi1015` |
| Header basic block | BB19 | BB40 |
| Zero-init predecessor | BB18 | BB39 |
| Backedge block | BB35 | BB54 |
| Loop body entry | BB20 | BB41 |
| Loop exit | BB36 | BB55 |
| Counter increment | `counter + 1` | `counter + 1` |
| Header predicate / transition | `ICMP_SGT(counter, N-1)`: true → skip body to backedge | same pattern |
| Backedge predicate / transition | `ICMP_SLT(counter+1, N)`: true → header | same pattern |
| Runtime N source | `space0:b2` row71, component1, byte offset **1140** | `space0:b2` row71, component2, byte offset **1144** |
| DXIL texture-index expressions | `phi708+10`, `phi708+11` | `phi1015+30`, `phi1015+31` |

The two comparisons load their source `N` from the **identical CBV binding, row and component** at both the header and backedge. The header expression `N-1` is independently traced to an integer `ADD` with literal `-1`. The increment `counter+1` was independently established in M34.

**Important limitations:**

- This establishes the **source of the loop bound as a CBV-supplied runtime value**, not a numerical limit. A loop count of `N` is conditional on unchanged valid `N` and supported no-overflow assumptions. The bytecode alone does not establish the value provided by the Forza game/runtime.
- Even a loop with a bound can access an invalid descriptor if the runtime does not bind sufficient array entries. Original arrays are `space6:t0[*]` **unbounded SRV ranges**, and the actual bound texture descriptor count remains unverified.
- No original shader material equation, exact texture identity, HLSL source, translated SPIR-V, or playable FH5 game port has been demonstrated.
- The study does not modify the stable on-phone Android app.

## Verification and local artifact

- **26/26 M35 new tests passed**, including original SHA-256, CFG completeness, all PHI predecessor sets, branch and predicate direction, threshold `ADD -1`, CBV resource provenance, rejection of modified branch targets, changed predicates, invalid resource components, SHA tampering, missing/duplicated ZIP entries.
- **26/26 M34** and **18/18 M33** regression tests passed: **70/70 combined**.
- Locally packaged `FH5_M35_CFG_Loop_Bound_Audit_Tools.zip` is **metadata-only**: 18 Python source, test, JSON, Markdown and checksum entries, **zero game shaders**.
- SHA-256 of this independent package: `2d91ab919bf842c13133511c4d08afcedfce6f4a0a48299b0f2ee9d0adb24dff`.
- Source verifier `m35_cfg_loop_bounds.py` SHA-256: `870255b48cb7b2804ef1292c603dd06c85d462e84027e3a2f346249eb0397721`.

## M36 engineering gate

Correlate original M25 `.materialbin` source samples and the game's CPU-side data/matching descriptor binding metadata (where legitimately available), to determine **whether runtime CBV `space0:b2`, row71 values are bounded** and whether at least `N+constant` texture descriptors are actually present. Do **not** infer a safe resource count from DXIL `unbounded` ranges.

## Technical specifications

- [LLVM bitcode FunctionCodes, BR/CMP2/PHI](https://llvm.googlesource.com/llvm-project/%2B/bf5d96c96c40e485327e8ddf4fb8f0ddae859e6f/llvm/include/llvm/Bitcode/LLVMBitCodes.h)
- [LLVM historical bitcode reader, conditional BR true/false destination ordering](https://github.com/llvm-mirror/llvm/blob/master/lib/Bitcode/Reader/BitcodeReader.cpp)
- [LLVM integer comparisons, ICMP_SGT=38 and ICMP_SLT=40](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/IR/InstrTypes.h)
