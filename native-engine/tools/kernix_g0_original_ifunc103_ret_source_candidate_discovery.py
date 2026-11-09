#!/usr/bin/env python3
"""Discover original GNU libc IFUNC103 x86 RET opcode source candidates.

NO native JIT, CALL, RET or ABI execution is proved by source disassembly.
The real FEX ARM64 hardware read and writer require distinct execution gates.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import decode_original_libc, LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

LIBC_BIAS=0x804000000
INDEX=103
OUTPUT="original-libc-IFUNC103-source-disassembled-RET-candidates-NOT-RUNTIME.json"
SOURCE_TXT="original-libc-IFUNC103-source-disassembled-RET-candidates-NOT-RUNTIME.txt"

def build(dist:Path):
    root=dist/"original-source-pinned-root"
    libc_path=root/"lib/x86_64-linux-gnu/libc.so.6"
    ldso_path=root/"lib64/ld-linux-x86-64.so.2"
    libc,ldso=libc_path.read_bytes(),ldso_path.read_bytes()
    assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
    assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
    records=decode_original_libc(libc)
    r=records[INDEX]
    assert r["index"]==INDEX and r["table"]=="DT_JMPREL" and r["r_type"]==37 and r["r_sym"]==0
    start=r["r_addend"]
    assert start==0xb4f90
    assert libc[source_offset(libc,start,4,5):][:4]==bytes.fromhex("f30f1efa")
    resolvers=sorted({entry["r_addend"] for entry in records if entry["r_type"]==37})
    after=[address for address in resolvers if address>start]
    scan_end=min(start+0x180,after[0] if after else start+0x180)
    assert start+8<=scan_end<=start+0x180
    cmd=["objdump","-d","-M","intel","--start-address="+hex(start),"--stop-address="+hex(scan_end),str(libc_path)]
    p=subprocess.run(cmd,check=True,text=True,capture_output=True)
    raw=p.stdout
    assert "file format elf64-x86-64" in raw
    assert hex(start)[2:] in raw
    candidates=[]
    for line in raw.splitlines():
        m=re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+([A-Za-z][A-Za-z0-9]*)",line)
        if not m: continue
        guest_offset=int(m.group(1),16)
        decoded=bytes.fromhex(m.group(2))
        mnemonic=m.group(3).lower()
        assert source_offset(libc,guest_offset,len(decoded),5)>=0
        off=source_offset(libc,guest_offset,len(decoded),5)
        assert libc[off:off+len(decoded)]==decoded,("objdump/source disagreement",hex(guest_offset))
        if mnemonic in ("ret","retq"):
            assert decoded==b"\xc3",("non-C3 RET variant needs independent plan",decoded.hex())
            candidates.append({"original_elf_virtual_address":hex(guest_offset),
                               "guest_source_RIP":hex(LIBC_BIAS+guest_offset),
                               "original_x86_opcode":"c3",
                               "source_ELF_RX_offset":hex(off),
                               "source_disassembler_mnemonic":mnemonic})
    assert candidates and len(candidates)<=24,("no source RET candidates: expand bounded disassembly only after inspection",scan_end)
    assert len({c["guest_source_RIP"] for c in candidates})==len(candidates)
    proof=json.loads((dist/"original-libc-IFUNC103-independently-source-verified-real-FEX-native-write-only.json").read_text())
    assert proof["source_original_ifunc_index"]==INDEX
    assert proof["source_original_resolver_guest_RIP"]==hex(LIBC_BIAS+start)
    assert proof["source_original_relocation_guest_target"]=="0x804202d68"
    assert proof["actual_native_hardware_new_qword"]=="0x8040c83a0"
    assert proof["IFUNC103_distinct_native_hardware_writer_independently_proven"] is True
    assert proof["nine_source_locked_native_hardware_tamper_controls_rejected"] is True
    assert proof["unique_original_libc_individual_native_writer_receipts"]==18
    assert proof["IFUNC103_resolver_CALL_RET_same_process_proven"] is False
    plan={"schema":"kernix.g0.original-ifunc103-source-disassembly-RET-candidates-NOT-RUNTIME.v1",
          "source_original_libc_sha256":LIBC_SHA,
          "source_original_ldso_sha256":LDSO_SHA,
          "original_IFUNC_source_index":INDEX,
          "original_resolver_source_RIP":hex(LIBC_BIAS+start),
          "original_resolver_ELF_RX_start":hex(start),
          "bounded_source_disassembly_stop":hex(scan_end),
          "next_source_resolver_start_if_any":hex(after[0]) if after else None,
          "source_disassembled_ret_candidates":candidates,
          "source_disassembly_ret_candidates_are_not_execution_proof":True,
          "native_FEX_original_IFUNC103_return_stack_hardware_read_proven":False,
          "original_ifunc103_same_guest_call_ret_writer_chain_proven":False,
          "previous_unique_native_hardware_writer_ledger":18,
          "all_147_source_relocations_closed":False,
          "Android_Bionic_Wine_Proton_games_proven":False}
    (dist/OUTPUT).write_text(json.dumps(plan,indent=2)+"\n")
    (dist/SOURCE_TXT).write_text(raw)
    print("KERNIX_G0_ORIGINAL_IFUNC103_SOURCE_RET_CANDIDATES_ONLY_NO_EXECUTION",",".join(c["guest_source_RIP"] for c in candidates))
    print("KERNIX_G0_ORIGINAL_IFUNC103_SOURCE_DISASSEMBLED_BOUNDS",hex(start),hex(scan_end))
    for c in candidates:
        print("KERNIX_G0_ORIGINAL_IFUNC103_SOURCE_ONLY_RET_CANDIDATE",c["guest_source_RIP"],c["source_disassembler_mnemonic"],c["original_x86_opcode"])

if __name__=="__main__":
    assert len(sys.argv)==2
    build(Path(sys.argv[1]))
