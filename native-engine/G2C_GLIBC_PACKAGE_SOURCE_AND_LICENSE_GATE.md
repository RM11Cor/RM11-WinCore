# KERNIX G2-C: exact x86 glibc/ld-linux provenance and distribution hold

**Status 2026-11-04: EXACT BINARY ORIGIN VERIFIED IN CI; DISTRIBUTION NOT APPROVED.**

## Immutable source identity

The already-proven G2-C Linux ARM64 pinned fixture was built from the
Ubuntu 24.04 x86 cross-sysroot. The original guest libc and interpreter
bytes in the authenticated fixture are byte-for-byte identical to the
installed package `libc6-amd64-cross` at version
`2.39-0ubuntu8cross1`, from Ubuntu `cross-toolchain-base`.

- `lib/x86_64-linux-gnu/libc.so.6`: 2,118,168 bytes;
  SHA-256 `7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906`.
- `lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`: 235,408 bytes;
  SHA-256 `cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae`.
- `lib64/ld-linux-x86-64.so.2` is exactly the same validated loader
  data, duplicated to avoid in-fixture symlinks.
- `bin/kernix-dynamic-app` is the original bounded x86 witness,
  13,344 bytes, SHA-256
  `e54a92cf77d1453c86b70accfd949b9e4521ddd5d629ba09c0dcac07a1397b4a`.

[CI 41810795716](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41810795716)
reinstalled `libc6-amd64-cross`, used `dpkg-query -S` to confirm
ownership of both actual binary paths and compared both against
the four exact original guest SHA-256 pin values. It also captured
the exact package's
`/usr/share/doc/libc6-amd64-cross/copyright`
and `/usr/share/common-licenses/LGPL-2.1` in
the **restricted audit artifact**, not in a user APK.
Tampering, missing package notice, source mismatch and a false
`licenses_reviewed_for_distribution=true` assertion all fail the gate.

The original G2-C guest input `PROVENANCE.json` still has
`licenses_reviewed_for_distribution=false` and
`android_apk_packaged=false`.
**Do not flip these solely because an upstream copyright file exists.**

## Distribution TODOs

Before ANY source/libc binary is published inside an APK:

1. Review the package's complete copyright record and verify licensing for
   each actual distributed object, including any GPL/LGPL exceptions,
   attribution and third-party components (not simply a filename check).
2. Bundle unmodified relevant copyright, LGPL license text and required
   accompanying notices with the app and the immutable guest input bundle.
3. Identify and make available corresponding source for the exact
   original x86 libc/ld-linux binaries and cross build, with a durable
   source-availability path or compliant written offer where required.
4. Confirm the independent guest executable's origin and required notices.
5. Make immutable guest files available ONLY to our app-private,
   content-hash-checked six-file installer; reject tar symlinks, paths
   outside the allowlist, altered bytes and replaced package files.
6. Validate byte-for-byte rootfs bytes and native FEX runner identity in
   the *final signed* Android APK. The runner must remain a subprocess
   with an eight-second watchdog and separate fatal/error reporting.
7. Explicitly qualify any genuine REDMAGIC/Android original FEX JIT
   fixed dynamic PIE trial separately from the Ubuntu ARM64 proof. Do NOT
   infer guest glibc startup, Wine or Windows game compatibility.

Existing signed `v0.21` previews do not contain the original x86
glibc/loader; they expose only the safe DATA-ONLY G2-C page probe.
The G2-C FEX candidate was built under
[CI 41809470149](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41809470149)
but is not packaged or installable, and Java's qualified-runner SHA
remains intentionally empty. This is a technical progress record,
not a legal opinion or redistribution authorization.
