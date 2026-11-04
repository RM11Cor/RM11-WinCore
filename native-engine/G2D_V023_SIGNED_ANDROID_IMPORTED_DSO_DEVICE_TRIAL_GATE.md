# KERNIX G2-D v0.23 — signed Android fixed MIT x86 cross-DSO CALL/RET trial

**Release evidence date:** 2026-11-04. **Status:** SIGNED APK VERIFIED; **G2-D has NOT YET been exercised on an Android device.** The user already reported v0.22 G2-C Android device PASS; this is a separate follow-up proof, not a game emulator.

## GitHub source and build

- Branch: `kernix-native-engine-v1`.
- [Signed APK release build 41834840683](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41834840683) — **SUCCESS**, source commit `f31f7e331ca7ee4e2226ad724cc503534abcf6b8`.
- GitHub artifact: `KERNIX-G2D-MIT-X86-DSO-Signed-OptIn-v0.23-APK` (ZIP contains APK and evidence).
- APK: `KERNIX-G2D-MIT-Import-OptIn-v0.23.apk`; 1,335,260 bytes.
- **APK SHA256**: `7704eb51a6b5249c5ffdf7a325e8699a3cf67126a2c256313470b37349b401d8`.
- Android package: `org.kernix.host`; versionCode **23**;
  versionName `0.23-g2d-mit-import-opt-in`.
- Stable APK v2 signer cert SHA256:
  `a74735bc30b53e590589d8ff5c233f72dc0e4ddf6e312939d668ae30c46b6f8e`.
  This is the same pinned KERNIX update signer as signed v0.22.
- Original `libFEXCore.so` SHA256:
  `f71397bf1bbedd03305c7127e442d674227fa54d15217cc7effb22dbaa9f4b1d`.
- Preserved G2-C Android original FEX guest runner SHA256:
  `62eee7a6344956d41bf3b1c0070c7f6c3b68d2a72f379f059f72da57557e2462`.
- New G2-D Android original FEX cross-DSO guest runner SHA256:
  `70ac0985691bee29dc420dc2dfea6cf308c505fe8d38cbd51e78a35443d3b460`.

CI verified actual signed APK ZIP member bytes, all six exact SHA256-pinned x86 ELF assets, the exact two ARM64 runner bytes, original FEXCore, original MIT license notice, no extra x86 ELFs, no glibc, single signed update certificate and monotonic versionCode. The APK was extracted separately from the signed CI artifact and all nine important inner ELF member hashes and 1,335,260-byte APK SHA rechecked.

## G2-D new fixture (not user-provided executables)

The only x86 files allowed for G2-D are:

| Signed APK asset | Size | SHA256 |
|---|---:|---|
| `assets/g2d-mit-import-v1/bin/kernix-g2d-import-app` | 50,504 | `a29be66289673e80cef5de115dfce0f05cb04599368f039c44c728ad0b2278a0` |
| `assets/g2d-mit-import-v1/lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1` | 50,048 | `8ec9bac9b3a21eeaedb4ec9c7071907a6074cbea9eb41f78591e176f0a27441e` |
| `assets/g2d-mit-import-v1/lib64/ld-kernix-g2d-mit-import-test.so.1` | 50,024 | `a37ed983c898512082749c5a9ec2cc3c10be8fd1adcffd4eaf09fb7346c068d2` |

A separate 16KiB-aligned real GNU x86 PLT `R_X86_64_JUMP_SLOT` relocation is validated for the fixed imported symbol `kernix_g2d_imported_value`. On native **Linux ARM64** [run 41830448479](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41830448479), the original FEXCore JIT executed the x86 CALL into the separate shared-object function, returned via x86 RET, and reached exact **RAX `0x4b45524e49584731`**, process exit 0. FEX's CALL/RET shadow stack is explicitly initialized with guarded anonymous memory.

The Android/Bionic source-built original FEX candidate [run 41833306718](https://github.com/RM11Cor/RM11-WinCore/actions/runs/41833306718) passed native ABI compile/link and original SHA pin audits. Android v0.23 is the **first** signed APK to package that separately qualified candidate.

## Bounded user-initiated Android test, not general emulator

VersionCode >=23 reveals a **G2-D explicit opt-in button** beside the retained v0.22 G2-C proof. The G2-D button opens an Arabic confirmation dialog. Only after the user approves, app-private storage is seeded with the fixed x86 MIT files from *signed APK assets* (not external files), rehashed, and only the fixed signed ARM64 original-FEX candidate is run with one exact fixed flag and an **8-second kill-on-timeout** child supervisor. The child reopens fixed app-private guest ELFs without symlink traversal, checks hashes/owner/mode, freezes readonly anonymous snapshots, performs precisely one trusted GOT relocation to the fixed external DSO, initializes FEX CALL/RET shadow stack and executes a single bounded x86 function CALL/RET.

**Expected true Android PASS from the Java child:**

```text
KERNIX_G2D_MIT_IMPORT_SIGNED_ASSET_SHA256_STAGED_NO_GUEST_EXEC
KERNIX_G2D_ANDROID_FEX_EXTERNAL_DSO_CALL_RET_VERIFIED_EXACT_RAX
```

The second marker is emitted ONLY after subprocess exit code **0** and exact original-FEX stdout:

```text
KERNIX_G2D_ANDROID_FEX_MIT_PINNED_PLT_CROSS_DSO_CALL_RETURN_PASS_V1
GUEST_RAX=0x4b45524e49584731
```

**The second marker has NOT been seen on an actual Android phone yet.** Report an error, timeout or crash accurately if observed; no uncontrolled reruns.

**Limits:** The signed PT_INTERP ELF is an intentionally nonfunctional placeholder. This probe manually applies only a single fixed `R_X86_64_JUMP_SLOT`; it does not launch a real dynamic interpreter, support arbitrary relocations/TLS, glibc, Linux distros, Wine/Proton, DXVK/VKD3D or Windows games. Even if the device test passes, those remain independent engineering milestones.

**Safety:** Install as the same-signer versionCode 23 update to v0.22; do NOT delete application storage or old proven source artifacts. One user-approved test only. Stop and report the first result if device becomes unstable, heats, or restarts.
