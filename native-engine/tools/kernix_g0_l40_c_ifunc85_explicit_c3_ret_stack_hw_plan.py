#!/usr/bin/env python3
"""Original GNU IFUNC85 one FEX PID explicit x86 C3 RET stack HARDWARE READ.

Extend authentic five GLOB_DAT + IFUNC85 resolver JIT+caller JIT+native
zero STLR test. Arm a real AArch64 hardware READ watch on the original
guest return-slot dynamically at the source-authentic resolver entry.
The actual native read must map to the GNU resolver's exact source C3 RET.
Source plan is not execution and never proves full ELF loader closure.
"""
from __future__ import annotations
import ast,hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_after_five_source_plan import (
    plan as prior_source, GDB as PRIOR_GDB, OUT as PRIOR_OUT, RET,
)
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    LIBC_BIAS, LDSO_BIAS, CALL, CALLER_RETURN, STORE,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40c.gnu-original-ifunc85-actual-c3-ret-native-read-source-plan.v1"
OUT="KERNIX-G0-C-IFUNC85-Exact-C3-RET-Hardware-Read-One-FEX-PID-SOURCE-ONLY.json"
GDB="kernix-g0-c-ifunc85-actual-C3-RET-hardware-stack-read-one-real-FEX-pid.gdb"
RET_ADDR=0x8040c860d

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_C_IFUNC85_C3_RET_SOURCE_FAIL_CLOSED: "+msg)

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    prev=prior_source(triad,ledger,repo,out/"previous")
    libc=(triad/"lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso=(triad/"lib64/ld-linux-x86-64.so.2").read_bytes()
    need(hashlib.sha256(libc).hexdigest()==LIBC_SHA
         and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
         and RET==RET_ADDR and prev["original_source_resolver_RET_guest_RIP"]==hex(RET_ADDR),
         "pinned genuine GNU source and original resolver RET")
    def bytes_at(data,guest,base,n,flags):
        return data[source_offset(data,guest-base,n,flags):][:n]
    need(bytes_at(libc,RET_ADDR,LIBC_BIAS,1,5)==b"\xc3"
         and bytes_at(libc,RET_ADDR-2,LIBC_BIAS,3,5)==bytes.fromhex("31c0c3")
         and bytes_at(ldso,CALL,LDSO_BIAS,2,5)==bytes.fromhex("ffd0")
         and bytes_at(ldso,CALLER_RETURN,LDSO_BIAS,4,5)==bytes.fromhex("4883c318")
         and bytes_at(ldso,STORE,LDSO_BIAS,3,5)==bytes.fromhex("498906"),
         "exact original GNU source CALL -> C3 RET -> caller -> store")
    src=(out/"previous"/PRIOR_GDB).read_text()
    pre="class IFUNC85OriginalGNUJITHeaderWatch(gdb.Breakpoint):"
    need(src.count(pre)==1 and src.count('state["resolver_jit_first"]=evt')==1,
         "exact native source resolver detection insertion points")
    watch_class=r'''state["actual_ret_hw_read"]=None
state["ret_stack_read_count"]=0
class OriginalIFUNC85ActualGuestC3RETRead(gdb.Breakpoint):
    def __init__(self,slot):
        self.slot=slot
        super().__init__("*(unsigned long long *)"+hex(slot),
                         type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_READ)
        self.silent=True
    def stop(self):
        try:
            state["ret_stack_read_count"]+=1
            n=state["ret_stack_read_count"]
            pid=gdb.selected_inferior().pid
            pc=int(gdb.parse_and_eval("$pc"))
            x28=int(gdb.parse_and_eval("$x28"))
            rsp=int(gdb.parse_and_eval("$x8"))
            rax=int(gdb.parse_and_eval("$x4"))
            retval=qword(self.slot)
            h=qword(x28)
            off=int.from_bytes(gdb.selected_inferior().read_memory(h,4).tobytes(),"little")
            tail=h+off
            entry=qword(tail+8)
            size=qword(tail+16)
            ops=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            c3=gdb.selected_inferior().read_memory(0x8040c860d,1).tobytes().hex()
            instruction=gdb.execute("x/i $pc-4",to_string=True).strip()
            evt={"pid":pid,"read_ordinal":n,"slot":hex(self.slot),
                 "return_value":hex(retval),"pc":hex(pc),"native_instruction":instruction,
                 "guest_rsp_after_read":hex(rsp),"guest_rax":hex(rax),
                 "FEX_guest_entry":hex(entry),"FEX_guest_size":size,
                 "FEX_native_ops":ops,"source_original_guest_ret_byte":c3}
            good=(pid==state["startup_pid"] and n<=16
                and pc>=0xffff00000000 and x28>=0xffff00000000
                and retval==0x80100fd5c
                and entry==0x8040c860d and size==1
                and 1<=ops<=128 and c3=="c3"
                and rsp in (self.slot,self.slot+8))
            if good:
                state["actual_ret_hw_read"]=evt
                jmark("IFUNC85_ORIGINAL_C3_RET_NATIVE_STACK_HW_READ",**evt)
                self.delete()
                return False
            jmark("IFUNC85_RET_STACK_ACCESS_UNCLASSIFIED",**evt)
            if n>=16:
                state["failure"]="actual original GNU C3 RET hardware read not source-matched"
                return True
            return False
        except Exception as e:
            state["failure"]="IFUNC85_RET_HARDWARE_READ_EXCEPTION:"+type(e).__name__+":"+str(e)
            jmark("IFUNC85_RET_READ_REJECT_EXCEPTION",error=state["failure"])
            return True
'''
    patched=src.replace(pre,watch_class+pre)
    from_line='''                state["resolver_jit_first"]=evt
                jmark("IFUNC85_RESOLVER_JIT_ENTRY_HW",**evt)'''
    to_line='''                state["resolver_jit_first"]=evt
                jmark("IFUNC85_RESOLVER_JIT_ENTRY_HW",**evt)
                OriginalIFUNC85ActualGuestC3RETRead(rsp)
                jmark("IFUNC85_SOURCE_C3_RET_STACK_HW_RWATCH_ARMED",
                      pid=pid,stack_slot=hex(rsp),expected_return=hex(ret),
                      source_guest_C3_RET="0x8040c860d",
                      original_ret_hardware_read_proven_yet=False)'''
    need(patched.count(from_line)==1,"unique exact source resolver entry where C3 return read watch is installed")
    patched=patched.replace(from_line,to_line)
    terminal="\nquit\n"
    need(patched.count(terminal)==1,"only one real native FEX GDB script quit")
    final=r'''python
assert state["failure"] is None,"native GNU IFUNC85 C3 RET failure: "+str(state["failure"])
assert state["actual_ret_hw_read"] is not None,"original C3 RET did not read guest return stack slot"
assert state["resolver_jit_first"] is not None and state["caller_jit_after"] is not None
assert state["ifunc85_native_store"] is not None
jmark("IFUNC85_EXACT_C3_RET_HW_READ_AND_SIX_NATIVE_WRITERS_ONE_FEX_PID",
      pid=state["startup_pid"],
      native_original_C3_RET_source_mapped_hardware_stack_read=True,
      original_source85_zero_to_zero_store=True,
      original_source85_resolver_and_caller_JIT_observed=True,
      stage_C_all_40_original_GNU_relocations_proven=False,
      full_original_dynamic_loader_closure_proven=False,
      Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''
    patched=patched[:patched.rfind(terminal)]+"\n"+final
    blocks=re.findall(r"(?:^|\n)python\n(.*?)\nend(?=\n|$)",patched,re.S)
    need(len(blocks)==8 and patched.count("\nrun\n")==1
         and patched.count("\ncontinue\n")==2
         and patched.count("\nquit\n")==1
         and patched.count("wp_class=gdb.WP_READ")==1,
         "native GNU stack hardware rwatch dynamic after resolver and before return")
    for code in blocks:ast.parse(code)
    out.mkdir(parents=True,exist_ok=True)
    (out/GDB).write_text(patched)
    doc={
        "schema":SCHEMA,
        "source85_original_GNU_resolver_entry":"0x8040c8570",
        "original_GNU_guest_indirect_CALL":hex(CALL),
        "source_original_guest_C3_RET_RIP":hex(RET_ADDR),
        "source_original_guest_C3_RET_byte":"c3",
        "original_GNU_caller_return_guest_RIP":hex(CALLER_RETURN),
        "original_GNU_source_writer":hex(STORE),
        "source_original_source85_target":"0x8042014c8",
        "native_ret_read_watch_armed_dynamically_at_actual_guest_RSP":True,
        "generated_native_GDB_script_sha256":hashlib.sha256(patched.encode()).hexdigest(),
        "native_guest_ret_stack_read_proven_by_source":False,
        "native_ifunc85_full_chain_proven_by_source":False,
        "full_40_stage_C_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False
    }
    (out/OUT).write_text(json.dumps(doc,indent=2)+"\n")
    print("KERNIX_G0_C_GNU_IFUNC85_EXACT_C3_RET_READ_HARDWARE_SOURCE_PLAN_NOT_EXECUTED")
    return doc

if __name__=="__main__":
    need(len(sys.argv)==5,"usage original_source_GNU_triad canonical147_ledger repo output")
    plan(*map(Path,sys.argv[1:]))
