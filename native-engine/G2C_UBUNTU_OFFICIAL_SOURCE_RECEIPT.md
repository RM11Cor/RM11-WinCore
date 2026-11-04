# KERNIX G2-C — Official Ubuntu corresponding source verification (2026-11-04)

**CI PASS:** [GitHub run 41812891866](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41812891866).

Exact binary source was previously proven: original pinned guest `libc.so.6`
and `ld-linux-x86-64.so.2` match package
`libc6-amd64-cross_2.39-0ubuntu8cross1` owned by Ubuntu
`cross-toolchain-base 68ubuntu5`.

We also verified these source files from the official Ubuntu archive:

- [glibc_2.39-0ubuntu8.dsc](https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/glibc_2.39-0ubuntu8.dsc)
- [glibc_2.39.orig.tar.xz](https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/glibc_2.39.orig.tar.xz)
- [glibc_2.39-0ubuntu8.debian.tar.xz](https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/glibc_2.39-0ubuntu8.debian.tar.xz)
- [cross-toolchain-base_68ubuntu5.dsc](https://archive.ubuntu.com/ubuntu/pool/main/c/cross-toolchain-base/cross-toolchain-base_68ubuntu5.dsc)
- [cross-toolchain-base_68ubuntu5.tar.xz](https://archive.ubuntu.com/ubuntu/pool/main/c/cross-toolchain-base/cross-toolchain-base_68ubuntu5.tar.xz)

CI verified pinned glibc .dsc SHA256
`af44b50b4aba75916f920337523d89698c465fafb720268bb87b2555000bea7a`
(2024 Ubuntu source release notice), glibc Ubuntu patch tar SHA256
`24d8627f34850f05554158b085499d255c67af27be9762d6a911b168852c1dd2`,
official Ubuntu-published cross-toolchain .dsc and tar MD5,
and actual tarball SHA256 against each checked .dsc inventory.
Negative tests reject altered source files and altered .dsc metadata.

Recorded CI output:
`dist/G2C-UBUNTU-2024-CORRESPONDING-SOURCE-RECEIPT-NO-DISTRIBUTION.json`
with `corresponding_source_artifacts_accessible=true` and the
source file SHA/size/URL inventory. Source archives were deleted after
verification, not added to APK nor included as binary artifacts.

**Caveats:** This is an archive digest/structural DSC identity receipt,
not a cryptographic PGP signature verification, reproducible binary build,
full LGPL legal review or authorization to redistribute original glibc.
It does not execute G2-C x86 code on Android. All
`distribution_approved`, `license_reviewed_for_distribution`,
`guest_dynamic_loader_executed_on_android` and `wine_or_windows_game_executed`
claims explicitly remain false.

The original KERNIX G2-C witness assembly source is
`native-engine/android-guest/kernix_g2c_dynamic_pie_direct_entry_witness.S`
with `SPDX-License-Identifier: MIT`, identical at Git blob
`2e917bded609e3e016fc19d981410cd8d0fcb35d`
to the independently FEX-executed pinned 2024 guest proof source.
The CI-pinned built ELF SHA256 remains
`e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a`.
The next distinct gate is to audit its original MIT notice and
add a single-source signed-APK release policy for a *future* fixed guest.
No guest ELF or glibc source was distributed in the existing v0.21 APK.
