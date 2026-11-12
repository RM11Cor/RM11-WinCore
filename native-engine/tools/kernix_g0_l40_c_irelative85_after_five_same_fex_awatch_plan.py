#!/usr/bin/env python3
"""G0 C: original GNU five real GLOB_DAT stores followed by IFUNC85 native AWATCH.

A same-value write does not reliably trip GDB watch. AWATCH traps reads
AND writes; require exact native STLR, host registers and FEX JIT x86
source 49 89 06 at guest 0x80100fd60. This prepares source only.
Actual original resolver CALL/RET remains separate acceptance gate.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_l40_c_first_five_rolling_original_fex_plan import (
    plan as first_five_plan, GDB as FIRST_FIVE_GDB,
)
from kernix_g0_l40_c_irelative85_original_resolver_source_gate import run as ifunc_source
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA, LDSO_SHA
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import STORE, LDSO_BIAS

SCHEMA="kernix.g0.l40c.original-gnu-five-globdat-then-ifunc85-one-fex-pid-awatch-source-only.v1"
OUT="KERNIX-G0-C-80-85-Five-Then-Zero-IFUNC85-One-FEX-AWATCH-SOURCE-ONLY.json"
GDB="kernix-g0-c-five-original-stores-then-irelative85-awatch-one-FEX-pid.gdb"
TARGET="0x8042014c8"
RESOLVER="0x8040c8570"
STORE_GUEST="0x80100fd60"
SOURCE_OPCODE="498906"

def need(cond,msg):
    if not cond: raise AssertionError("KERNIX_C_IFUNC85_AFTER_FIVE_SOURCE_FAIL_CLOSED: "+msg)

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    five=first_five_plan(triad,ledger,repo,out/"five-source")
    old=ifunc_source(triad,ledger,out/"ifunc85-source")
    need(five["source_indices"]==[80,81,82,83,84]
         and five["new_fifth_native_writer_proven_by_source_only"] is False
         and old["source_index"]==85 and old["source_table"]=="DT_RELA"
         and old["relocation"]=="R_X86_64_IRELATIVE"
         and old["candidate_resolver_guest_RIP"]==RESOLVER
         and old["original_slot_guest_address"]==TARGET
         and old["original_slot_file_qword"]=="0x0",
         "source-authentic five GNU GLOB_DAT then one original IFUNC85")
    ldso=(triad/"lib64/ld-linux-x86-64.so.2").read_bytes()
    libc=(triad/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    need(hashlib.sha256(ldso).hexdigest()==LDSO_SHA
         and hashlib.sha256(libc).hexdigest()==LIBC_SHA,
         "actual immutable original GNU ELF sources")
    offset=source_offset(ldso,STORE-LDSO_BIAS,3,5)
    need(hex(STORE)==STORE_GUEST and ldso[offset:offset+3].hex()==SOURCE_OPCODE,
         "exact original GNU ldso MOV [R14],RAX IFUNC store opcode")
    ret=source_offset(libc,0xc860b,3,5)
    need(libc[ret:ret+3].hex()=="31c0c3",
         "source resolver XOR EAX,EAX RET exists, not runtime proven")
    script=(out/"five-source"/FIRST_FIVE_GDB).read_text()
    need(script.rstrip().endswith("quit") and script.count("\nquit\n")==1
         and script.count('FIVE_REAL_ORIGINAL_GLOB_DAT_80_84_WRITERS_SAME_ARM64_FEX_PID')==1,
         "pinned original five writer native GDB script")
    head=script[:script.rfind("\nquit\n")]+"\n"
    extra=r'''python
source85=__SOURCE85__
assert state["failure"] is None and [v["index"] for v in state["hits"]]==[80,81,82,83,84]
pid85=gdb.selected_inferior().pid
assert pid85==state["startup_pid"] and pid85>0
target85=int(source85["target"],16)
assert qword(target85)==0,"original GNU IFUNC85 prewrite qword must be zero"
for bp in list(gdb.breakpoints() or []):
    if isinstance(bp,OriginalWriter):
        bp.delete()
state["ifunc85_access_count"]=0
state["ifunc85_native_store"]=None
class OriginalIRELATIVE85ZeroAccess(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*(unsigned long long *)"+source85["target"],
                         type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_ACCESS)
        self.silent=True
    def stop(self):
        try:
            state["ifunc85_access_count"]+=1
            n=state["ifunc85_access_count"]
            pid=gdb.selected_inferior().pid
            pc=int(gdb.parse_and_eval("$pc"))
            x4=int(gdb.parse_and_eval("$x4"))
            x19=int(gdb.parse_and_eval("$x19"))
            x28=int(gdb.parse_and_eval("$x28"))
            instr=gdb.execute("x/i $pc-4",to_string=True).strip()
            hdr=qword(x28)
            hoff=int.from_bytes(gdb.selected_inferior().read_memory(hdr,4).tobytes(),"little")
            tail=hdr+hoff
            entry=qword(tail+8)
            size=qword(tail+16)
            native_count=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            guest_bytes=gdb.selected_inferior().read_memory(entry,3).tobytes().hex()
            actual=qword(target85)
            evt={"index":85,"pid":pid,"access_ordinal":n,"target":hex(target85),
                 "value":hex(actual),"pc":hex(pc),"x4":hex(x4),"x19":hex(x19),
                 "x28":hex(x28),"instruction":instr,"FEX_guest_entry":hex(entry),
                 "FEX_guest_size":size,"FEX_native_ops":native_count,
                 "source_x86_3bytes":guest_bytes}
            good=(pid==state["startup_pid"] and n<=48
                and pc>=0xffff00000000 and x28>=0xffff00000000
                and x4==0 and x19==target85 and actual==0
                and re.search(r"\bstlr\s+x4,\s*\[x19\]",instr)!=None
                and entry==int(source85["store_guest"],16) and size==3
                and 1<=native_count<=64 and guest_bytes=="498906")
            if good:
                state["ifunc85_native_store"]=evt
                jmark("IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE",**evt)
                return True
            jmark("IFUNC85_UNCLASSIFIED_AWATCH_ACCESS",**evt)
            if n>=48:
                state["failure"]="bounded native IFUNC85 access never matched original GNU store"
                return True
            return False
        except Exception as e:
            state["failure"]="IFUNC85_NATIVE_AWATCH_EXCEPTION:"+type(e).__name__+":"+str(e)
            jmark("IFUNC85_REJECT_EXCEPTION",error=state["failure"])
            return True
OriginalIRELATIVE85ZeroAccess()
jmark("IFUNC85_AWATCH_ARMED_AFTER_FIVE_IN_SAME_PID",
      pid=pid85,index=85,target=source85["target"],prewrite="0x0",
      expected_guest_store=source85["store_guest"],source_resolver=source85["resolver"],
      five_indices=[80,81,82,83,84],native_writer_proven_yet=False)
end
continue
python
assert state["failure"] is None,"genuine IFUNC85 failed closed: "+str(state["failure"])
assert state["ifunc85_native_store"] is not None,"original GNU IFUNC85 native store missing"
assert gdb.selected_inferior().pid==state["startup_pid"]
jmark("FIRST_SIX_ORIGINAL_GNU_SOURCE_NATIVE_STORES_ONE_FEX_PID",
      pid=state["startup_pid"],indices=[80,81,82,83,84,85],
      source85_zero_to_zero_real_native_store=True,
      original_IFUNC85_resolver_ENTRY_and_RET_chain_proven=False,
      stage_C_all_40_original_writers_proven=False,
      all_147_one_guest_loader_proven=False,
      Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''.replace("__SOURCE85__",repr({"target":TARGET,"resolver":RESOLVER,"store_guest":STORE_GUEST}))
    combined=head+extra
    blocks=re.findall(r"(?:^|\n)python\n(.*?)\nend(?=\n|$)",combined,re.S)
    need(len(blocks)==6 and combined.count("\nrun\n")==1
         and combined.count("\ncontinue\n")==2
         and combined.count("\nquit\n")==1
         and combined.count("wp_class=gdb.WP_ACCESS")==1
         and combined.count("IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE")==1,
         "five then IFUNC85 bounded hardware AWATCH in one PID")
    for code in blocks: ast.parse(code)
    out.mkdir(parents=True,exist_ok=True)
    (out/GDB).write_text(combined)
    obj={
        "schema":SCHEMA,
        "original_libc_sha256":LIBC_SHA,"original_ldso_sha256":LDSO_SHA,
        "previous_five_source_indices":[80,81,82,83,84],
        "original_IRELATIVE_source_index":85,
        "original_IRELATIVE_target":TARGET,"original_IRELATIVE_old_qword":"0x0",
        "candidate_source_resolver_guest_entry":RESOLVER,
        "original_GNU_ldso_x86_store_guest_RIP":STORE_GUEST,
        "original_GNU_ldso_x86_store_opcode":SOURCE_OPCODE,
        "native_fex_gdb_script_sha256":hashlib.sha256(combined.encode()).hexdigest(),
        "actual_real_FEX_native_zero_to_zero_writer_proven_by_plan":False,
        "original_resolver_entry_or_return_executed_proven_by_plan":False,
        "all_six_same_guest_native_writers_proven_by_plan":False,
        "stage_C_40_native_source_writers_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(obj,indent=2)+"\n")
    print("KERNIX_C_IFUNC85_ORIGINAL_GNU_AWATCH_AFTER_FIVE_SOURCE_PREPARED_NATIVE_UNPROVEN")
    return obj

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original_SHA_GNU_triad canonical147_ledger repository_root output")
    plan(*map(Path,sys.argv[1:]))
