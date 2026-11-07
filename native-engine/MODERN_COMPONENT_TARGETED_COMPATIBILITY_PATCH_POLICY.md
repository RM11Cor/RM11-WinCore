# KERNIX — modern-component-first targeted compatibility patch policy

Date: 2026-11-07. This is the user's clarified engineering objective: **do not make old component releases the product solution**. Treat an older successful release as an A/B reference for a regression investigation, then fix the root cause in a currently supported, source-pinned **modern** component or in the component-to-component integration boundary. The existence of this policy is not a completed patch or game compatibility result.

## Rule: modern supported baseline + narrowly verified game corrections

1. Select a recent, actively supported and *device-compatible* upstream source revision as the BASELINE for each subsystem (FEX, Wine/Proton, DXVK, VKD3D-Proton, Turnip/Mesa Vulkan, DXGI, Android host). Do not simply pick the numerically highest tag: API/ABI support, driver extensions, hardware limitations, tested stability and security issues govern baseline selection. New releases may fix bugs **and** introduce regressions.
2. Prefer upstream fixes, maintained fixes or clean source-level integration adapters. When a legacy release works and the baseline fails, compare its commits/features and exact observed guest/driver traces; isolate what behavior, ABI assumption, extension requirement, ordering, resource accounting or shader optimization changed. Do **not** copy the old binary/engine wholesale, hide an unsupported GPU feature, or fabricate CPU/VRAM values.
3. Classify the FIRST real failure and test the boundary: game -> Win32/Wine/Proton API -> DXGI/D3D12 or DXVK -> Vulkan ICD/Turnip -> Android and FEX/guest memory. A game working on an older version is evidence of a difference, **not** proof that the newer component itself is faulty; incompatibility can be due to version negotiation, paired runtime/driver, profile settings, launcher, memory or hardware.
4. Produce a **small, source-reviewed compatibility patch** on top of the modern version, preferably upstreamable. If a localized game-specific toggle/feature/workaround is possible, gate it by exact game/executable build and runtime requirements; never enable it for every game or change system-wide CPU/GPU behavior. If a patch necessarily affects all programs, independently test broad regressions.
5. Document source repo and modern commit hash, game executable SHA256/version, older known-good reference version, minimal triggering input/trace, cause hypothesis, actual changed code, patch id and SHA, dependencies, licenses, ABI, and rollback plan. Maintain reproducible build artifacts and a patch applicability/rebase check on each upstream upgrade.
6. Test: unmodified modern baseline FAIL -> old known-good reference (if reproducible) PASS -> modified modern baseline PASS **under the same device/game conditions** -> independent regressions PASS for unrelated games and same game with patch OFF. Tests must measure first frame, session stability, CPU features/memory budget, driver error, frame times, and thermals instead of accepting one launcher splash or FPS overlay.
7. If source-backed patch cannot be implemented correctly, keep the failure explicitly OPEN with logs, unsupported feature / resource constraint and next hypothesis. A legacy version may remain as an **optional controlled diagnostic or user fallback** to preserve playability, but it is **not** the proposed KERNIX long-term compatibility fix.

## Correct layer for typical cases

| Observed difference | Diagnose and fix in modern stack |
| --- | --- |
| Older DXVK works, modern DXVK fails in a D3D9/10/11 game | Verify game D3D API, regression diff, DXVK state/feature reporting and pairing with Wine/DXGI/driver; patch precise compatibility behavior. **Do not use DXVK to fix D3D12.** |
| Older VKD3D-Proton/driver works, modern stack fails in D3D12 game | Compare VKD3D-Proton D3D12 feature queries, pipeline/barrier/compiler behavior, Vulkan extension and format support, DXGI adapter/budgets and paired Turnip/Vulkan ICD; patch the actual owning component or adapter. |
| Older FEX works, modern CPU/JIT fails | Reproduce guest x86 CPUID/XGETBV, exact instructions, flags/TSO/memory ordering, guest page protections, JIT invalidation and SIGBUS/SIGSEGV; fix instruction translation or runtime bridge without lying to game CPU detection. |
| Older Wine/Proton works, modern fails | Diff Win32 API behavior, DLL overrides/imports, initialization, memory allocation, launcher prerequisites, runtime dependencies and component ABI contracts; patch the responsible Wine/Proton or bridge code. |
| Failure only with particular component combination | Solve cross-version ABI/feature-negotiation mismatch, not a global downgrade. Pin the corrected tested pair and add a regression for that integration. |
| Mobile hardware genuinely lacks required feature or memory budget | Report accurate limit and investigate a standards-correct implementation/fallback where possible; do not claim universal support by spoofing capabilities. |

## Example (hypothetical, not a factual game diagnosis)

A game launches on a legacy VKD3D-Proton and fails on a modern build. Capture the D3D12/DirectX feature calls and Vulkan failure in both cases, compare the interface with the exact Wine/DXGI and Turnip versions, identify a changed synchronization path or unsupported Vulkan extension if logs prove it, implement the smallest fix in the MODERN source tree, then run same-game and independent regression checks. The legacy version serves as evidence only.

## Release gate and current state

- Core original GNU ELF/FEX/RELRO correctness remains the active independent phase. This policy applies once Windows and graphics layers can be tested on the actual Android device; it is not an authorization to skip the current phase or modify working user installations.
- A game-specific compatibility patch is *accepted* only after source review, reproducible before/after proof, modern baseline functionality and regression tests. Experimental patches cannot silently become production defaults or overwrite user game files.
- No claim is made that every game will run on every Android phone or at a particular FPS. An anecdotal video is a research lead; exact settings and hardware must be verified rather than inferred.
