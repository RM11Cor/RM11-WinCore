# CarX Street original Windows PE GameAssembly source — owner's actual v1.2 results

Checkpoint: 2026-11-12. This is original user-owned CarX Street PC binary data analysis.
**No proprietary code, extracted x86 bytes, generated proprietary C++,
source game assets or published game APK are committed to the repository.**

Owner archive:
CarX_GameAssembly_AOT_DiverseUnwind_v1.2.zip
SHA-256: a725b41e2cafac8c7266b682e45a4e871b484e6c95d75521b114927b1a52bfef
Archive size: 172,911 bytes. Original Win64 GameAssembly.dll size: 142,049,792 bytes.

Independently read-only audited the original ZIP, manifest and every source member:
- 256 original x86-64 code region members; 24,583 executable-code bytes.
- 256 distinct original Win64 .xdata/UNWIND_INFO header RVAs in the source
  sampling selection (one per original bounded code region). No duplicate primary
  unwind metadata RVA in this v1.2 sample.
- 429 total unique original .xdata UNWIND_INFO binary records.
- 0 code or xdata SHA-256 mismatches, 0 missing or undeclared members.
- 256/256 original source unwind chains reached an unchained xdata record.
- 28 source code regions have one unwind xdata record (no CHAININFO).
- 199 regions have two xdata records (one CHAININFO link).
- 28 regions have three xdata records (two CHAININFO links).
- 1 region has four xdata records (three CHAININFO links).
- Therefore **228/256 original regions are chained** and **258 original
  CHAININFO parent source references** appear across them.

Main engineering discovery:
- All 258 CHAININFO parent executable BeginAddress/EndAddress ranges refer
  to source code that was NOT included among the 256 selected code members.
- These 258 parent source ranges have 258 distinct BeginAddress values
  with no conflicting length declaration in the original metadata.
- Combined parent source code lengths: 31,738 bytes (not actual code bytes yet).
- Largest original parent range length: 1,148 bytes.
- All 258 parent ranges are within a safe 4KiB-per-fragment read bound.

The original source .pdata data is NOT a game method-name table. A chained parent
does NOT automatically prove the full original method has been captured.
A "complete unwind chain" is a metadata property, NOT proof of complete
callable x86 IL2CPP function boundaries or original game execution.

For the 28 original source regions with no CHAININFO, private linear x86-64
binutils objdump decoding found indicative instruction characteristics:
- 24/28 contain call instructions in the linear byte walk.
- 17/28 have RIP-relative operands.
- 8/28 contain SIMD/XMM instructions.
- All 28 contain branches in linear source decoding.
- 11/28 contain RET in the linear byte walk.
- None can be certified as self-contained based on linear instructions
  and source metadata alone. These are overlapping feature counts, not
  reachability-correct CFG results. Actual AOT gate must still run.

## Engineering implementation based on actual source

PortLab v1.3 updates GameAssemblyCodeBridge.java to read exactly the PE
CHAININFO-referenced original parent executable ranges from the owner's
game directory, in **read-only SAF mode** with Win64 PE section mapping.

- A specific dedicated Win64ParentCodePolicy.java checks <=4096 bytes per
  parent range, <=2 MiB total original parent bytes, <=1024 parent members.
- File-backed original parent code fragments are stored under
  parents/rva_XXXXXXXX.bin in the user-selected private ZIP.
- Independent SHA256 and exact BeginAddress/EndAddress/unwind RVA metadata are
  recorded with each parent source code fragment.
- Existing 256 bounded original PE function regions and 429 actual UNWIND_INFO
  records are retained in the same source ZIP.
- No full 142 MB original GameAssembly.dll is exported and no game files are
  modified by this read-only feature.

Python analyze_carx_win64_xdata_zip.py accepts schema v3 and verifies
the source executable parent code bytes, parent metadata provenance,
Win64 chained xdata, exact member lengths, SHA256 and source budgets
before any x86-to-ARM64 AOT admission. The static AOT screener also
accepts schema v3, but does NOT present chained source snippets as
executed gameplay or complete Unity game methods.

Source parent code bytes had not been available in v1.2, so this is
a strictly new required original-code input, not a repeat of old
bundle/catalg/fake-Vulkan tests.

## What will count as actual game code progress after owner v1.3 source ZIP

1. Verify authentic original parent bytes and source xdata parent pointer.
2. Build multi-segment original Win64 CFG with complete parent/child code ranges.
3. Map unresolved RIP references/relocations, callee targets and Unity IL2CPP
   runtime interactions; validate actual original method identity.
4. Execute an original source method reference on x86 and statically AOT
   translate it to Android Bionic ARM64, compare outputs on device.
5. Later integrate original Unity scene/physics/graphics after first method proof.

No original CarX gameplay method executed and no real game frame rendered as
of this report. The 330/330 synthetic x86 vs AArch64 comparisons and actual
Android NDK synthetic shared ELF prove toolchain components, not original
CarX runtime execution.
