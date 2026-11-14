#!/usr/bin/env python3
"""Patch only pinned 02e24ca FEXCore ARM64 JIT TSO memory path for diagnostics.

On REDMAGIC 11 Pro R3D14 tombstone, source-authentic ld.so executed:
  LDAR X7,[X20]    x20=0x4000000819 (8-byte unaligned)
  SIGBUS BUS_ADRALN at JIT PC+0x407e4.

Do not patch JIT machine code or guest ELF. Rebuild full FEXCore from upstream
source with conservative DMB ISH + ordinary LDR/STR in the non-RCPC GPR
TSO path and in the MemCpyTSO/MemorySetTSO helpers.
AArch64 ordinary memory access to normal memory supports unaligned addresses;
LDAR/STLR and other atomics have strict alignment. DMB ISH before AND after
each load/store keeps ordering conservative but may be significantly slower.
This is a diagnostic correctness patch, NOT performance-optimized final code.
"""
from pathlib import Path
import subprocess,hashlib,json,sys
if len(sys.argv)!=2:raise SystemExit("usage: patch_fex_tso_alignment.py /tmp/fex-src")
root=Path(sys.argv[1])
commit=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
assert commit=="02e24ca5c01ed0c864466ed573db347336f70170",("wrong-upstream",commit)
target=root/"FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp"
source=target.read_text()
oldsha=hashlib.sha256(source.encode()).hexdigest()
def repl(old,new,want=1):
    global source
    num=source.count(old)
    assert num==want,("source_lock_mismatch",old,num,want)
    source=source.replace(old,new)
B="dmb(ARMEmitter::BarrierScope::ISH);"
# This is the path the device's FEX JIT actually used: non RCPC GPR LDAR.
for size,word in [("i16Bit","ldarh(Dst, MemReg)"),
                   ("i32Bit","ldar(Dst.W(), MemReg)"),
                   ("i64Bit","ldar(Dst.X(), MemReg)")]:
    normal={"i16Bit":"ldrh(Dst.W(), MemReg)",
            "i32Bit":"ldr(Dst.W(), MemReg)",
            "i64Bit":"ldr(Dst.X(), MemReg)"}[size]
    repl(f"case IR::OpSize::{size}: {word}; break;",
         f"case IR::OpSize::{size}: {B} {normal[:-1]}, 0); {B} break;")
# Likewise 16/32/64bit non RCPC GPR stores to unaligned host addresses.
for size,word in [("i16Bit","stlrh(Src, MemReg)"),
                   ("i32Bit","stlr(Src.W(), MemReg)"),
                   ("i64Bit","stlr(Src.X(), MemReg)")]:
    normal={"i16Bit":"strh(Src.W(), MemReg)",
            "i32Bit":"str(Src.W(), MemReg)",
            "i64Bit":"str(Src.X(), MemReg)"}[size]
    repl(f"case IR::OpSize::{size}: {word}; break;",
         f"case IR::OpSize::{size}: {B} {normal[:-1]}, 0); {B} break;")
# MemCpyTSO helper: even a REP MOVS may be unaligned and atomics can fault.
# Keep the existing byte-atomic path untouched; for multi-byte use a full
# ordering barrier around ordinary unaligned-capable LDR/STR.
for n,atomic,normal in [
    (2,"ldaprh(TMP4.W(), TMP3)","ldrh(TMP4.W(), TMP3)"),
    (4,"ldapr(TMP4.W(), TMP3)","ldr(TMP4.W(), TMP3)"),
    (8,"ldapr(TMP4, TMP3)","ldr(TMP4, TMP3)"),
    (2,"ldarh(TMP4.W(), TMP3)","ldrh(TMP4.W(), TMP3)"),
    (4,"ldar(TMP4.W(), TMP3)","ldr(TMP4.W(), TMP3)"),
    (8,"ldar(TMP4, TMP3)","ldr(TMP4, TMP3)"),
]:
    repl(f"case {n}: {atomic}; break;",
         f"case {n}: {B} {normal[:-1]}, 0); {B} break;")
for n,atomic,normal in [
    (2,"stlrh(TMP4.W(), TMP2)","strh(TMP4.W(), TMP2)"),
    (4,"stlr(TMP4.W(), TMP2)","str(TMP4.W(), TMP2)"),
    (8,"stlr(TMP4, TMP2)","str(TMP4, TMP2)"),
]:
    repl(f"case {n}: {atomic}; break;",
         f"case {n}: {B} {normal[:-1]}, 0); {B} break;",2)
# MemSetTSO helper: same alignment class on destination stores.
for n,atomic,normal in [
    (2,"stlrh(Value.W(), TMP2)","strh(Value.W(), TMP2)"),
    (4,"stlr(Value.W(), TMP2)","str(Value.W(), TMP2)"),
    (8,"stlr(Value.X(), TMP2)","str(Value.X(), TMP2)"),
]:
    repl(f"case {n}: {atomic}; break;",
         f"case {n}: {B} {normal[:-1]}, 0); {B} break;")
assert source != target.read_text()
assert source.count("dmb(ARMEmitter::BarrierScope::ISH);")>=26
assert "ldar(Dst.X(), MemReg)" not in source
assert "stlr(Src.X(), MemReg)" not in source
assert "ldar(TMP4, TMP3)" not in source
assert "stlr(TMP4, TMP2)" not in source
target.write_text(source)
newsha=hashlib.sha256(source.encode()).hexdigest()
# Audit only the exact source file & platform adaptation, never silently
# broaden a patch to context / threading / syscalls / guest ELF.
log=root/"r3d15-fex-jit-unaligned.json"
log.write_text(json.dumps({"schema":"carx.r3d15.fexcore-alignment-patch.v1",
 "upstream_repo":"FEX-Emu/FEX","upstream_commit":commit,
 "file":"FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp",
 "original_file_sha256":oldsha,"patched_file_sha256":newsha,
 "source_change":"GPR_TSO_NON_RCPC_AND_MEMCPY_MEMSET_BYTE_SAFE_DIAGNOSTIC_FULL_BARRIERS",
 "no_guest_binary_patch":True,"native_device_proof":False,
 "diagnostic_only_performance_may_be_lower":True},indent=2)+"\n")
print("R3D15_ORIGINAL_FEXCORE_SHA_PINNED_MEMORY_JIT_ALIGNMENT_PATCH_PASS",oldsha,newsha)
