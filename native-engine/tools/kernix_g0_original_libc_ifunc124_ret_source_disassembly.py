#!/usr/bin/env python3
"""Disassemble immutable ORIGINAL GNU x86 libc IFUNC124 resolver source RETs.

Source/ELF inventory ONLY, NOT a FEX native execution or hardware READ proof.
Require independently certified IFUNC124 new source target WRITE (39/147) first.
No copied source RET offset from IFUNC102/103. Bound by next source resolver.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from kernix_g0_original_libc_relocation_type_transition_gate import (
    decode_original_libc, LIBC_SHA, LDSO_SHA
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

INDEX=124
BIAS=0x804000000
OUT="original-libc-IFUNC124-true-source-x86-C3-RET-candidates-NOT-RUNTIME.json"
TEXT="original-libc-IFUNC124-true-source-x86-C3-RET-candidates-NOT-RUNTIME.txt"
CERT="original-libc-IFUNC124-source-locked-distinct-real-FEX-ARM64-native-HW-WRITE-INDEPENDENT-PROOF.json"

def generate(dist:Path):
    root=dist/"original-source-pinned-root"
    libcfile=root/"lib/x86_64-linux-gnu/libc.so.6"
    ldsofile=root/"lib64/ld-linux-x86-64.so.2"
    assert libcfile.is_file() and not libcfile.is_symlink()
    assert ldsofile.is_file() and not ldsofile.is_symlink()
    libc,ldso=libcfile.read_bytes(),ldsofile.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    rows=decode_original_libc(libc)
    row=rows[INDEX]
    assert row["index"]==INDEX and row["table"]=="DT_JMPREL"
    assert row["table_index"]==38 and row["r_type"]==37 and row["r_sym"]==0
    start=row["r_addend"]
    assert start==0xb2ed0
    assert source_offset(libc,start,8,5)>=0  # source verified by original ELF SHA
    assert row["source_guest_target"]=="0x804202c78"
    proof=json.loads((dist/CERT).read_text())
    assert proof["original_source_libc_sha256"]==LIBC_SHA
    assert proof["original_source_ldso_sha256"]==LDSO_SHA
    assert proof["original_source_ifunc_index"]==INDEX
    assert proof["source_original_resolver_guest_RIP"]==hex(BIAS+start)
    assert proof["original_source_target"]=="0x804202c78"
    assert proof["new_source_resolver_result_original_libc_RX"] is True
    assert proof["new_unique_original_ifunc124_native_hardware_writer_independently_proven"] is True
    assert proof["unique_original_libc_native_hardware_writer_target_count"]==39
    assert proof["original_IFUNC124_resolver_CALL_C3_RET_native_stack_HW_READ_proven"] is False
    assert proof["ten_original_native_hardware_log_corruptions_rejected"] is True
    resolvers=sorted({r["r_addend"] for r in rows if r["r_type"]==37})
    later=[x for x in resolvers if x>start]
    stop=min(start+0x800,later[0] if later else start+0x800)
    assert start+8<=stop<=start+0x800
    p=subprocess.run(
      ["objdump","-d","-M","intel","--start-address="+hex(start),
       "--stop-address="+hex(stop),str(libcfile)],
      check=True,capture_output=True,text=True)
    raw=p.stdout
    assert "file format elf64-x86-64" in raw
    candidates=[]
    for line in raw.splitlines():
        m=re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+([A-Za-z][A-Za-z0-9]*)",line)
        if not m: continue
        va=int(m.group(1),16)
        decoded=bytes.fromhex(m.group(2))
        op=m.group(3).lower()
        assert start<=va<stop
        off=source_offset(libc,va,len(decoded),5)
        assert libc[off:off+len(decoded)]==decoded,("actual immutable x86 instruction mismatch",hex(va))
        if op in ("ret","retq"):
            assert decoded==b"\xc3",("unsupported different original RET opcode",hex(va),decoded.hex())
            candidates.append({
              "original_elf_virtual_address":hex(va),
              "guest_source_RIP":hex(BIAS+va),
              "original_x86_opcode":"c3",
              "source_ELF_RX_offset":hex(off),
              "source_disassembler_mnemonic":op
            })
    assert 1<=len(candidates)<=48,("no bounded candidate original C3 RET or too many",stop)
    assert len({x["guest_source_RIP"] for x in candidates})==len(candidates)
    receipt={
      "schema":"kernix.g0.original-libc-IFUNC124-source-only-bounded-x86-RET-candidate-v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "original_IFUNC_source_index":INDEX,
      "original_resolver_source_RIP":hex(BIAS+start),
      "source_disassembled_from_ELF_start":hex(start),
      "source_disassembly_bound_before_next_resolver":hex(stop),
      "next_original_source_resolver_offset":hex(later[0]) if later else None,
      "source_disassembled_RET_candidates":candidates,
      "source_disassembly_RET_candidates_are_NOT_native_execution_proof":True,
      "native_FEX_original_IFUNC124_return_stack_hardware_read_proven":False,
      "original_ifunc124_same_guest_call_ret_writer_chain_proven":False,
      "previous_unique_native_hardware_writer_ledger":39,
      "full_147_original_libc_dynamic_relocations_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False
    }
    (dist/OUT).write_text(json.dumps(receipt,indent=2)+"\n")
    (dist/TEXT).write_text(raw)
    print("KERNIX_G0_IFUNC124_ORIGINAL_X86_SOURCE_RET_CANDIDATES_ONLY_NOT_RUN count=",len(candidates))
    print("KERNIX_G0_IFUNC124_ORIGINAL_X86_SOURCE_BOUNDS",hex(start),hex(stop))
    for x in candidates:
        print("KERNIX_G0_IFUNC124_SOURCE_ONLY_C3_RET_CANDIDATE",x["guest_source_RIP"],x["original_x86_opcode"])

if __name__=="__main__":
    assert len(sys.argv)==2
    generate(Path(sys.argv[1]))
