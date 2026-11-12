# KERNIX G0-L40-C — original GNU IFUNC85 zero-to-zero real native hardware write (same FEX PID)

Date: 2026-11-12. Branch: `kernix-native-engine-v1`. **Diagnostic Linux ARM64 FEX; not Android or Wine execution.**

## Independently verified original source stores

- Prior: genuine original GNU `GLOB_DAT` indices 80..84 five real native ARM64 FEX `STLR` writes in one PID, [Actions #43157219154](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43157219154) **SUCCESS**, 44 forged original writer controls rejected.
- New: [Actions #43160956967](https://github.com/RM11Cor/RM11-WinCore/actions/runs/43160956967) **SUCCESS** on pinned original GNU libc, ld-linux and FEX host. Exact **same native ARM64 FEX PID 3346** performed original source writer events for **80,81,82,83,84,85**. Independent original ELF / native trace gate rejected **20 false #85 hardware store claims**.
- Source `#85` is a genuine original x86 GNU `DT_RELA R_X86_64_IRELATIVE` relocation, initially **zero** at exact target guest qword `0x8042014c8`. Native GDB **AWATCH**, not value-change WATCH, trapped source `#85` after the first five writes.
- The same native hardware access PC `0xffffa4ce96a4` corresponded to preceding **`stlr x4, [x19]`**, with `x4=0`, `x19=0x8042014c8`, source-authenticated FEX JIT guest entry **`0x80100fd60`**, 3 x86 bytes **`49 89 06`**, two native operations. **This classifies an actual zero-to-zero writer rather than mistaking an AWATCH read for a write**.
- Historical individual source writer receipts `147/147` remain a **different evidence category**. Across distinct single-batch FEX processes, the currently demonstrated writer windows are A 40 + B 40 + C 6 = **86/147** target writes observed in their respective windows, **not 86 relocations closed in one process**.

## IFUNC resolver gate is not closed by a store

Source-only immutable GNU libc ELF establishes IFUNC85 candidate resolver guest RIP **`0x8040c8570`** and source x86 `xor eax,eax; ret` at `0x8040c860b..0x8040c860d`. Source x86 loader indirect CALL **`0x80100fd5a`**, caller site **`0x80100fd5c`**, and final store **`0x80100fd60`**.

These source bytes and a real native zero-to-zero store alone **do not prove** actual resolver entry, exact C3 RET/stack hardware read, guest return restoration, or full ifunc behavior. Separate native JIT-header watch tests are being developed and must remain fail-closed.

## Persistent release blockers

- Remaining **34** indices in Stage C 86..119; original 16 `JUMP_SLOT` (86..101) and 18 `IRELATIVE` (102..119) need real type-specific dynamic evidence in one stage-C process.
- Stage D 120..146 (27 indices) is separately unproven as a complete one-process window.
- Original GNU main-versus-ldso RELRO owner/VMA/permission proof, full relocation closure, Android/Bionic host bridge, Wine/Proton, Vulkan rendering, first game frame and FPS **are not certified**.
- No fake guest registers, mocked zero writer, loosened RELRO checks, synthetic source-only acceptance, or finished APK claim.

Follow-up: bounded original guest-JIT resolver entry and caller site, explicit C3 RET hardware stack read and independent negative controls, followed by the next actual JMPREL windows.
