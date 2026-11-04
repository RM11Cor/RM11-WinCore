# KERNIX G2-C — combined guest source/notice hold and actual signed APK firewall

**Dated 2026-11-04. Scope: verified Linux CI and signed-APK inspection, NOT an Android G2-C JIT device proof.**

## Verified source and legal/evidence hold

[CI 41814981497](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41814981497) — **SUCCESS**, including:
- Original SHA-pinned four-file x86 ELF64 fixture, including the independently GNU-built original MIT assembly witness.
- Exact distro `libc6-amd64-cross=2.39-0ubuntu8cross1` ownership/hash evidence and its actual copyright notice.
- Corresponding original Ubuntu `glibc_2.39-0ubuntu8` and `cross-toolchain-base_68ubuntu5` source tarball SHA256 inventories.
- Full LGPL-2.1 notice, original MIT source, checksum and Git-blob identity.
- Hostile negative tests: tampered guest ELF, corrupted license notice, altered source provenance, mismatched distro package and falsely approved redistribution.
- Deterministic output `dist/G2C-COMBINED-SOURCE-LICENSE-PRE-RELEASE-HOLD.json`, with `release_action=HOLD_NO_APK_NO_GUEST_EXECUTION`, `redistribution_approved=false`, `qualifying_signed_fex_runner_sha256=null` and all Android G2-C dynamic guest/runtime/game claims **false**.

This is a technical input/notice consistency gate, **not a legal conclusion**. Original source availability and MIT/LGPL notices do not themselves establish complete distro redistribution compliance.

## Real signed Android APK content scanned

[Signed APK CI 41814948466](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41814948466) — **SUCCESS**, with exact stable package signer/version verification and a new full-ZIP-content gate from `tools/kernix_g2c_apk_guest_release_firewall.py`.

The gate runs **after** `gradle :app:assembleRelease` on the actual APK. It inspects all contained ZIP members (not merely filenames) and:

- Rejects duplicates, path traversal, symbolic links, encrypted members and oversized decompressed entries.
- Rejects exact SHA-256 of any of the four original G2-C guest ELF files even when renamed.
- Rejects any standalone x86_64 ELF64 file in the host-only preview APK.
- Rejects forbidden guest libc, loader, or fixed G2-C JIT runner entry names.
- Rejects misplaced/wrong-ABI native libraries; requires Android ARM64 ELF for bundled libraries.
- Rejects G2-C direct-entry candidate CLI/guest-pass signatures hidden in any Android native library.
- Requires the original ARM64 `libFEXCore.so` and **data-only** `libkernix_g2c_data_only_child.so`.
- Produces `dist/G2C-SIGNED-APK-GUEST-NO-SHIP-FIREWALL.json` with native library SHA-256 checksums and explicit `g2c_dynamic_pie_executed_on_android=false`.

The same archive scanner passed independent adversarial tests against renamed exact fixed guest ELF, renamed libc, unrelated x86 ELF, malicious ZIP paths, hidden JIT markers, symlinks, duplicates, missing data-only child, and incorrect ARM64 ABI, within [CI 41814981497](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41814981497).

## Release boundary and next milestone

The signed host preview is still version **0.21** and is functionally unchanged for the REDMAGIC page/host G1 checks. It does **NOT** contain a qualified G2-C JIT original FEX candidate or original guest libc/loader, despite the original Android candidate having linked successfully in [CI 41809470149](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41809470149).

**Do not set a FEX runner SHA or make G2-C executable in the user UI** merely because these checks pass. Priorities before a bounded G2-C on-device x86 dynamic PIE JIT test: full per-file redistribution terms, corresponding-source/notice distribution review, package the exact signed qualified runner and immutable fixture only when lawful, assert identical bytes/runner hash in the final APK, and run an explicit 8-second child gate against REDMAGIC with failure and thermal safeguards. Android guest interpreter, glibc startup, Wine/PE, DXVK/VKD3D and Windows games remain separate and unverified.
