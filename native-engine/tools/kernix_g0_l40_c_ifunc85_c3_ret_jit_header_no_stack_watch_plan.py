#!/usr/bin/env python3
"""Observe genuine GNU IFUNC85 C3 RET JIT header WITHOUT a crashing stack watch.

The original ARM64 Linux FEX host had fatal SIGBUS/SIGSEGV (exit139) when
a native hardware rwatch/awatch was installed on the guest return stack.
This method keeps only the previously validated FEX JIT-state and IFUNC85
target watchpoints. A source-mapped RET JIT header is NOT native evidence
of the precise stack load; that remains a separate release gate.
"""
from __future__ import annotations
import ast,hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_after_five_source_plan import (
    plan as original_plan, GDB as ORIGINAL_GDB,
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import LIBC_BIAS
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

SCHEMA="kernix.g0.l40c.original-gnu-ifunc85-c3-ret-jit-guest-header-no-stack-watch-source-plan.v1"
OUT="KERNIX-G0-C-IFUNC85-C3-RET-JIT-Header-No-Stack-Hardware-Watch-SOURCE-ONLY.json"
GDB="kernix-g0-c-original-ifunc85-c3-ret-jit-entry-no-stack-rwatch.gdb"
RET=0x8040c860d
RETVAL=0x80100fd5c

def need(test,reason):
    if not test: raise AssertionError("KERNIX_G0_C_IFUNC85_C3_RET_HEADER_SOURCE_FAIL_CLOSED: "+reason)

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    base=original_plan(triad,ledger,repo,out/"original")
    libc=(triad/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    need(hashlib.sha256(libc).hexdigest()==LIBC_SHA
         and base["original_source_resolver_RET_guest_RIP"]==hex(RET)
         and libc[source_offset(libc,RET-LIBC_BIAS,1,5)]==0xc3,
         "original GNU ELF SHA and exact source C3 RET at genuine IRELATIVE85 resolver")
    script=(out/"original"/ORIGINAL_GDB).read_text()
    start='state["resolver_jit_first"]=None'
    need(script.count(start)==1,"exact true original GNU IFUNC85 initial JIT state")
    script=script.replace(start,start+'\nstate["ret_jit_header"]=None')
    marker='            if entry==0x8040c8570 and state["resolver_jit_first"] is None:'
    need(script.count(marker)==1,"actual source authenticated JIT state callback")
    block=r'''            if entry==0x8040c860d and state["ret_jit_header"] is None:
                sourcebyte=gdb.selected_inferior().read_memory(0x8040c860d,1).tobytes().hex()
                original_rsp_val=qword(rsp)
                evt={"pid":pid,"scan":scan,"native_pc":hex(nativepc),
                     "guest_entry":hex(entry),"guest_size":size,"native_ops":ops,
                     "guest_rsp":hex(rsp),"guest_return_qword":hex(original_rsp_val),
                     "guest_rax":hex(rax),"source_C3_byte":sourcebyte}
                state["ret_jit_header"]=evt
                jmark("IFUNC85_C3_RET_JIT_GUEST_HEADER_OBSERVED_NO_HW_STACK_READ",**evt)
'''
    script=script.replace(marker,block+marker)
    close='''jmark("IFUNC85_SAME_PID_RESOLVER_JIT_CALLER_AND_ZERO_WRITER_TRACE",'''
    need(script.count(close)==1,"real native six store+resolver/caller terminal for source evidence")
    script=script.replace(close,
'''assert state["ret_jit_header"] is not None,"original GNU C3 RET JIT header not reached"
assert state["ret_jit_header"]["source_C3_byte"]=="c3","source original C3 byte missing"
jmark("IFUNC85_C3_RET_JIT_HEADER_WITH_CALLER_AND_NATIVE_ZERO_STORE_ONLY",
      pid=state["startup_pid"],original_guest_C3_RET_source_JIT_header_seen=True,
      exact_guest_C3_RET_stack_hardware_read_proven=False,
      stage_C_40_original_GNU_relocations_proven=False,
      Android_Bionic_Wine_Proton_games_proven=False)
'''+close)
    chunks=re.findall(r"(?:^|\n)python\n(.*?)\nend(?=\n|$)",script,re.S)
    need(len(chunks)==7 and script.count("\nrun\n")==1
         and script.count("\ncontinue\n")==2 and script.count("\nquit\n")==1
         and "wp_class=gdb.WP_READ" not in script
         and script.count("wp_class=gdb.WP_ACCESS")==1
         and script.count("wp_class=gdb.WP_WRITE")>=2,
         "no stack watch: FEX JIT-header watch and existing original zero writer AWATCH only")
    for chunk in chunks:ast.parse(chunk)
    out.mkdir(parents=True,exist_ok=True)
    (out/GDB).write_text(script)
    report={
        "schema":SCHEMA,
        "original_libc_SHA256":LIBC_SHA,"original_ldso_SHA256":LDSO_SHA,
        "original_source85_C3_RET_guest_RIP":hex(RET),
        "original_source85_C3_RET_byte":"c3",
        "original_gnu_caller_return_guest_address":hex(RETVAL),
        "native_GDB_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
        "guest_stack_hardware_watch_armed_in_this_test":False,
        "actual_source_ret_JIT_header_proven_by_plan":False,
        "exact_original_guest_RET_hardware_stack_read_proven_by_plan":False,
        "full_original_GNU_loader_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_C_IFUNC85_REAL_C3_RET_JIT_HEADER_SOURCE_PLAN_NO_STACK_WATCH_NO_NATIVE_PROOF")
    return report

if __name__=="__main__":
    need(len(sys.argv)==5,"usage SHA-original GNU triad canonical147 repo output")
    plan(*map(Path,sys.argv[1:]))
