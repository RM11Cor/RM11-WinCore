#!/usr/bin/env python3
"""Stage C IFUNC85: attempt true original GNU resolver JIT-entry/caller sequence
after five original GLOB_DAT and actual zero-to-zero native STORE in ONE FEX PID.

Do not infer a C3 RET instruction from caller-site transition alone.  Even
if source-locked resolver and caller JIT guest entries are both observed,
an independent RET stack hardware-read gate must prove explicit x86 C3.
"""
from __future__ import annotations
import ast,hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_irelative85_after_five_same_fex_awatch_plan import (
    plan as six_source_plan, GDB as SIX_GDB, TARGET, RESOLVER, STORE_GUEST,
)
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    CALL,CALLER_RETURN,LDSO_BIAS,LIBC_BIAS,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40c.ifunc85-authentic-gnu-resolver-caller-JIT-guest-source-seven-gates-v1"
OUT="KERNIX-G0-C-IFUNC85-Resolver-JIT-Caller-After-Five-SOURCE-ONLY.json"
GDB="kernix-g0-c-original-irelative85-resolver-JIT-caller-real-one-FEX-pid.gdb"
RET=0x8040c860d

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_C_IFUNC85_GUEST_RESOLVER_SOURCE_FAIL_CLOSED: "+msg)

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    six=six_source_plan(triad,ledger,repo,out/"six-source")
    libc=(triad/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(triad/"lib64/ld-linux-x86-64.so.2").read_bytes()
    need(hashlib.sha256(libc).hexdigest()==LIBC_SHA
         and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
         and six["original_IRELATIVE_source_index"]==85
         and six["candidate_source_resolver_guest_entry"]==RESOLVER,
         "same SHA genuine GNU IFUNC85 and immutable C five + zero write")
    def bsrc(image,offset,n,access):
        return image[source_offset(image,offset,n,access):][:n]
    need(bsrc(ldso,CALL-LDSO_BIAS,2,5)==bytes.fromhex("ffd0")
         and bsrc(ldso,CALLER_RETURN-LDSO_BIAS,4,5)==bytes.fromhex("4883c318")
         and bsrc(libc,int(RESOLVER,16)-LIBC_BIAS,4,5)==bytes.fromhex("f30f1efa")
         and bsrc(libc,RET-LIBC_BIAS-2,3,5)==bytes.fromhex("31c0c3"),
         "actual original x86 GNU CALL indirect, return site, resolver ENDBR64, XOR/RET source bytes")
    src=(out/"six-source"/SIX_GDB).read_text()
    anchor="OriginalIRELATIVE85ZeroAccess()\n"
    need(src.count(anchor)==1 and src.rstrip().endswith("quit"),
         "original native FEX six-store GDB exact arming point")
    injection=r'''state["resolver_jit_first"]=None
state["caller_jit_after"]=None
state["jit_watch_scan"]=0
class IFUNC85OriginalGNUJITHeaderWatch(gdb.Breakpoint):
    def __init__(self):
        self.stateaddr=int(gdb.parse_and_eval("$x28"))
        super().__init__("*(unsigned long long *)"+hex(self.stateaddr),
                         type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_WRITE)
        self.silent=True
    def stop(self):
        try:
            state["jit_watch_scan"]+=1
            scan=state["jit_watch_scan"]
            if scan>16384:
                state["failure"]="IFUNC85 real FEX header hardware scan exceeded 16384"
                jmark("IFUNC85_JIT_SCAN_BOUNDED_REJECT",count=scan)
                return True
            pid=gdb.selected_inferior().pid
            nativepc=int(gdb.parse_and_eval("$pc"))
            x28=int(gdb.parse_and_eval("$x28"))
            if pid!=state["startup_pid"] or x28!=self.stateaddr:
                state["failure"]="IFUNC85 FEX native state/PID changed during resolver"
                return True
            h=qword(x28)
            if h==0:return False
            offset=int.from_bytes(gdb.selected_inferior().read_memory(h,4).tobytes(),"little")
            tail=h+offset
            entry=qword(tail+8)
            size=qword(tail+16)
            ops=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            rsp=int(gdb.parse_and_eval("$x8"))
            rax=int(gdb.parse_and_eval("$x4"))
            r14=int(gdb.parse_and_eval("$x19"))
            if scan<=16 or scan%512==0 or entry in (0x8040c8570,0x80100fd5c,0x80100fd60):
                jmark("IFUNC85_JIT_HEADER_DIAGNOSTIC",pid=pid,scan=scan,
                      guest_entry=hex(entry),guest_size=size,native_ops=ops,
                      guest_rsp=hex(rsp),guest_rax=hex(rax),guest_r14=hex(r14))
            if entry==0x8040c8570 and state["resolver_jit_first"] is None:
                ret=qword(rsp)
                evt={"pid":pid,"scan":scan,"native_pc":hex(nativepc),
                     "guest_entry":hex(entry),"guest_size":size,"native_ops":ops,
                     "guest_rsp":hex(rsp),"guest_stack_return":hex(ret),
                     "guest_rax":hex(rax),"guest_r14":hex(r14)}
                state["resolver_jit_first"]=evt
                jmark("IFUNC85_RESOLVER_JIT_ENTRY_HW",**evt)
            if (entry==0x80100fd5c and state["resolver_jit_first"] is not None
                    and state["caller_jit_after"] is None):
                evt={"pid":pid,"scan":scan,"native_pc":hex(nativepc),
                     "guest_entry":hex(entry),"guest_size":size,"native_ops":ops,
                     "guest_rsp":hex(rsp),"guest_rax":hex(rax),"guest_r14":hex(r14)}
                state["caller_jit_after"]=evt
                jmark("IFUNC85_CALLER_JIT_RETURN_SITE_HW",**evt)
            return False
        except Exception as e:
            state["failure"]="IFUNC85_FEX_JIT_WATCH_EXCEPTION:"+type(e).__name__+":"+str(e)
            jmark("IFUNC85_JIT_REJECT_EXCEPTION",error=state["failure"])
            return True
IFUNC85OriginalGNUJITHeaderWatch()
jmark("IFUNC85_FEX_GUEST_JIT_STATE_WATCH_ARMED",
      pid=state["startup_pid"],source_resolver="0x8040c8570",
      original_caller_site="0x80100fd5c",source_guest_RET="0x8040c860d",
      native_RET_stack_read_proven_yet=False)
'''
    patched=src.replace(anchor,injection+anchor)
    needle="\nquit\n"
    need(patched.count(needle)==1,"single original native GDB terminal")
    end=r'''python
assert state["failure"] is None,"IFUNC85 resolver/caller JIT source fail-closed: "+str(state["failure"])
assert state["resolver_jit_first"] is not None,"original source IFUNC85 resolver JIT not reached"
assert state["caller_jit_after"] is not None,"original GNU IFUNC85 caller return-site JIT not reached"
jmark("IFUNC85_SAME_PID_RESOLVER_JIT_CALLER_AND_ZERO_WRITER_TRACE",
      pid=state["startup_pid"],
      source85_resolver_JIT_entry_seen=True,
      source85_caller_JIT_return_site_seen=True,
      source85_real_zero_store_seen=state["ifunc85_native_store"] is not None,
      exact_original_C3_RET_opcode_native_stack_read_proven=False,
      stage_C_all_40_GNU_relocations_proven=False,
      all_147_one_guest_loader_proven=False,
      Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''
    patched=patched[:patched.rfind(needle)]+"\n"+end
    blocks=re.findall(r"(?:^|\n)python\n(.*?)\nend(?=\n|$)",patched,re.S)
    need(len(blocks)==7 and patched.count("\nrun\n")==1
         and patched.count("\ncontinue\n")==2 and patched.count("\nquit\n")==1
         and patched.count("IFUNC85OriginalGNUJITHeaderWatch()")==1
         and patched.count("IFUNC85_RESOLVER_JIT_ENTRY_HW")==1,
         "GNU original JIT native hardware watchers follow five in one PID")
    for block in blocks:ast.parse(block)
    out.mkdir(parents=True,exist_ok=True)
    (out/GDB).write_text(patched)
    doc={
        "schema":SCHEMA,
        "previous_five_indices":[80,81,82,83,84],"ifunc_original_source_index":85,
        "source_guest_resolver":RESOLVER,"original_source_resolver_RET_guest_RIP":hex(RET),
        "source_guest_call_RIP":hex(CALL),"source_guest_caller_return_RIP":hex(CALLER_RETURN),
        "source_guest_IFUNC_writer":STORE_GUEST,"source_guest_target":TARGET,
        "original_GNU_source_CALL_opcode":"ffd0","original_resolver_RET_opcode":"c3",
        "original_guest_stack_return_expected":hex(CALLER_RETURN),
        "native_GDB_script_sha256":hashlib.sha256(patched.encode()).hexdigest(),
        "source_plan_proves_native_resolver_entry":False,
        "source_plan_proves_native_caller_return":False,
        "source_plan_proves_native_RET_stack_read":False,
        "source_plan_proves_six_real_writers_one_PID":False,
        "full_original_GNU_loader_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(doc,indent=2)+"\n")
    print("KERNIX_G0_C_ORIGINAL_IFUNC85_RESOLVER_CALLER_JIT_HARDWARE_SOURCE_PLAN_ONLY")
    return doc

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original_triad ledger147 repo output")
    plan(*map(Path,sys.argv[1:]))
