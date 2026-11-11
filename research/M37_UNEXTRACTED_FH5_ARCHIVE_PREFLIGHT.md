# FH5 M37 — Local game archive preflight without unpacking

## User state and immediate delivery

The user has **downloaded a complete-game archive to an Android phone but has not extracted it**. M36 found a conditional glass resource-index capacity formula, but did not observe actual `b2` uniform values or populated descriptor table count. Therefore, M37 first supplies an **on-device, metadata-only archive inspector** rather than demanding another large download or premature full extraction.

### Deliverable

`tools/FH5_M37_Archive_Probe.py` — self-contained Python 3 program in this branch.

- Reads a normal ZIP **central directory directly** using Python stdlib `zipfile`, with no game file decompression.
- If the original archive is RAR or 7z, uses installed `7zz`, `7z` or `7za` to list headers **without extracting files**. Requires only the external archive-listing utility, not Python pip packages.
- Supports archive-path override for generic filenames, interactive selection in `/sdcard/Download`, and multipart-name checks for `.part01.rar`, `.7z.001`, `.zip.001`.
- Reports approximate archive structure, relevant binary-extension counts, candidate game EXE name, and the nested original `media/_library/Shaders.zip` member when present.
- Does not run, install, modify, copy, extract, or delete the user's game. Reads entry names/sizes only; does **not** test all file CRCs or the whole download's integrity.
- Writes a shareable small report `/sdcard/Download/FH5_M37_ARCHIVE_REPORT.json`, clearly labelled with `runtime_b2_row71_values_available=false`, `runtime_space6_srv_descriptor_capacity_available=false`, and `m36_real_runtime_capacity_gate_evaluable=false`.

Run in Termux Ubuntu/proot, with the Python file in Download:
```bash
python3 /sdcard/Download/FH5_M37_Archive_Probe.py
```
If several archives are present, choose the user's FH5 item from the printed menu; if a game archive has an unusual name, use `--archive "/sdcard/Download/EXACT_FILE_NAME"`.

### Offline tests and checks

- Local development version: `python3 FH5_M37_Archive_Probe.py --self-test` succeeded on a **synthetic ZIP**, validating nested Shaders.zip, game EXE, shader reference, dangerous path names (not extracted), and zero runtime claims.
- Local 7-Zip technical listing parser separately exercised with a **mock 7z CLI output**: two entries found, correct source selection.
- The GitHub standalone variant includes its own `--self-test` fixture and extends that fixture to check nested game EXE names.
- **User's actual downloaded FH5 archive has not been accessed, listed or validated yet**, as the ZIP/RAR/7z file is still on the user's Android phone, not attached to this conversation.

## What M36 remains missing

From the original compiled glass shader, the two loop bounds come from **space0:b2, row 71, components 1 and 2** (`N1`, `N2`). Original DXIL uses selected `space6:t0[*]` descriptors with maximum dynamic indices `N1+10`, `N2+30`, under M36's nonnegative and no-overflow preconditions.

The conditional *four-handle-only* capacity gate is:
```
required = max((N1+11 if N1>0 else 0), (N2+31 if N2>0 else 0))
populated_space6_descriptor_capacity >= required
```
This can only be evaluated with original **runtime** CBV byte values and descriptor table bindings from the **same render state**. Neither this metadata-only archive inventory nor simply unpacking the original game can supply them.

### Next step

User runs the published read-only script on the device and shares `FH5_M37_ARCHIVE_REPORT.json`. Based on actual archive format and indexed contents, design **minimal selective extraction**, if needed, while preserving phone storage. Any future GPU runtime test requires instrumenting the supported D3D12/VKD3D resource-binding path, not guessing from static binaries.

**No new APK, playable FH5 game port, Vulkan shader translation, safe descriptor bound or final material formula has been demonstrated in M37.** M23–M25 stable Android viewer branches were left untouched.

## Provenance

Uses M25 material report (8 materialbin observations, 3 glass members), M27 compiled evidence (4 verified stages), M33–M36 SHA-checked static DXIL audit and conditional resource analysis. No original proprietary game data is embedded in this GitHub branch.
