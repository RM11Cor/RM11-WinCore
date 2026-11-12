# CarX Street G0 — genuine owner GameAssembly v1.3 source and precise missing executable intervals

Checkpoint date: 2026-11-12. Branch: carx-street-pc-port-v1.
Independent from KERNIX and FH5. All original Windows x86 bytes
are kept in the owner's private local ZIP, not committed to GitHub.

## Authentic owner-supplied ZIP: data integrity

CarX_GameAssembly_AOT_ParentCode_v1.3.zip
SHA256: d421b1ac642af8528dd9472549b04f4b2075969b1e182c9895c90f7e4e8b7233
Archive length: 251,334 bytes.

Locally parsed EVERY actual original source member and independently
verified its SHA256 against source manifest, byte length, original
Win64 .xdata chained pointer, and source-code file membership.

- 256 distinct original x86-64 child .pdata source code regions,
  total 24,583 bytes.
- 429 unique original PE .xdata UNWIND_INFO byte records.
- 258 actual original CHAININFO parent executable code fragments,
  total 31,738 bytes. All 258 SHA256 values verified, 0 missing.
- 258 chained parent references across 228 of the 256 child samples.
- Original unwind chain lengths per sample: 28 of length 1,
  199 of length 2, 28 of length 3, 1 of length 4.
- 944 total original archive members: manifest + 256 child code +
  429 unique xdata + 258 unique parent code.
- No duplicate ZIP paths, missing referenced members or SHA mismatches.

This validates that v1.3 has read real parent executable bytes,
NOT that any sampled area corresponds to a complete original Unity
IL2CPP gameplay method.

## First structural source findings (GNU objdump, linear only)

A first read-only original x86-64 GNU objdump *linear* analysis of
source fragments counted features (categories can overlap):

- Parent fragments: 230/258 contain at least one branch,
  191/258 contain CALL, 157/258 have RIP-relative operands,
  48/258 use XMM/YMM/ZMM SIMD operands, only 16/258 contain RET
  in the linear byte walk.
- Child fragments: 215/256 contain CALL, 145/256 contain
  branch, 105/256 have RIP-relative references and 54/256
  SIMD operands.
- First *linear* disassembly of combined selected parent/child
  source intervals detected 91 source groups with one or more
  direct inter-segment branch/call targets, including 90
  parent-to-child and 2 child-to-parent source-group observations.
  These counts can overlap and are NOT full reachable CFG results.
- 243/256 groups still have original direct calls outside the
  bounded selected source ranges; 170 have direct out-of-range jumps,
  by that same preliminary linear disassembly.
- Example original child RVA 0x89529A has a parent source range
  ending at 0x895279, with a 33-byte missing intervening code
  interval. Its parent can branch directly into the child,
  but other root paths need the omitted bytes.
- More generally: joining CHAININFO metadata is not itself a
  machine-code CALL/JMP edge. Always use source executable CFG
  to establish a true branch path and original Win64 ABI behavior.

## The next immediately actionable source gap

A deterministic, source-only comparison of all original child and
parent BeginAddress/EndAddress pairs in v1.3 found:

- Exactly 146 distinct positive-length executable RVA intervals
  between adjacent selected parent/child source regions.
- Total missing RVA bytes: **47,416**.
- Maximum single missing source interval: **2,145** bytes.
- 93 gap intervals <= 256 bytes; 125 <= 512 bytes.
- Among 228 chained groups, 83 have zero positive-length gaps
  in those observed ranges. This does NOT imply no missing callees
  or other functions; it only concerns the selected known regions.

These original bytes do not exist in v1.3 ZIP, so reconstructing them
by guesses or zeros would be a false game port proof.

## Implemented source-driven engineering

1. native-port/recompiler/x64_multisegment_cfg.py:
   a reachability-first bounded original x86 PE CFG which can
   follow actual local CALL/JMP targets across separately mapped
   verified parent and child source ranges; distinguishes unmapped
   external calls/jumps, indirect calls and RIP-dependent data,
   and never invents a control-flow edge from CHAININFO metadata.

2. native-port/recompiler/triage_original_carx_parent_child_cfg.py:
   owner-private original v1.3 source ZIP validation (xdata,
   parent SHA and child SHA) before multi-segment root/child CFG
   triage. Does not publish original game bytes or run original code.

3. Android PortLab v1.4 (source bridge, not playable):
   GameAssemblyCodeBridge.java computes missing executable RVA
   intervals between known original parent and child code ranges
   and exports the RAW original PE executable data into
   gaps/rva_XXXXXXXX.bin, each <=4KiB, <=2MiB aggregate,
   with per-fragment SHA and exact original RVA metadata.

4. Python source validator now accepts archive schema v4,
   verifies every declared original gap range against validated
   parent/child interval boundaries and source SHA256. The
   multi-segment CFG can include independently verified gap bytes
   as bounded data ranges. Because the interval may include
   unrelated code or padding, provenance remains a raw PE
   executable gap, not a proven method body.

5. Synthetic independent tests cover actual parent-to-child
   x86 direct jump and call edges, original xdata chain integrity,
   missing external dependencies, incomplete fallthrough, wrong
   gap RVA/size/hash and fabricated source membership.

No original gameplay execution, x86 reference equivalence for
a complete original CarX method, original Android ARM64 GameAssembly
method execution, game physics, Unity scene or first game frame has
yet been proven.

Next gate: owner-export source ZIP v1.4, then a reachable,
dependency-aware original method graph, actual x86 reference
behavior and Android Bionic ARM64 native execution evidence.
