#!/usr/bin/env python3
"""40 original GNU DT_RELA0..39 live native FEX GDB watchpoints in ONE process.

All source tuples are independently regenerated from immutable original
GNU libc+ldso SHA256, as a source-only plan. Ten GDB windows of four
hardware writepoints; rearm ONLY while the SAME inferior is stopped.
Three R_X86_64_64, fifteen TLS TPOFF64 and twenty-two GLOB_DAT retain
different original GNU CPU register/JIT semantics. Failure must identify
individual source index and window. No native result is implied here.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l40_a_original_rela0_39_source_windows import (
    build as original_source,SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN

SCHEMA="kernix.g0.l40a.one-real-arm64-fex-process-forty-original-source-typed-watch-windows-plan.v1"
OUT="KERNIX-G0-L40-A-One-Real-FEX-PID-Original-40-Type-Specific-Hardware-GDB-Source-Only.json"
GDB="kernix-g0-l40-a-forty-original-gnu-stores-one-FEX-pid.gdb"

# GDB executes this ONLY against an actual Linux AArch64 FEX original
# guest instance. Source-only validation parses syntax; actual CPU
# values and true relocation correctness require a separate real run.
GDB_INIT=r'''set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
python
import gdb,json,re
rows=__ROWS__
state={"pid":None,"hits":[],"window":0,"failure":None,"armed":False}
def mark(kind,**kv):
    gdb.write("KERNIX_G0_L40_A_"+kind+" "+json.dumps(kv,sort_keys=True)+"\n")
def memory_qword(address):
    return int.from_bytes(gdb.selected_inferior().read_memory(address,8).tobytes(),"little")
def arm_window(w):
    assert 0<=w<10
    assert state["pid"]==gdb.selected_inferior().pid and state["pid"]>0
    assert len(state["hits"])==4*w
    for row in rows[4*w:4*w+4]:
        addr=int(row["target"],16)
        current=memory_qword(addr)
        if current!=0:
            state["failure"]="late watch: next original source already changed before arming"
            mark("FAIL_EARLY_SOURCE_WRITE",index=row["index"],window=w+1,pid=state["pid"],target=row["target"],actual=hex(current))
            raise AssertionError(state["failure"])
    state["window"]=w
    for row in rows[4*w:4*w+4]:
        OriginalWriter(row)
    mark("ARM_WINDOW",window=w+1,pid=state["pid"],
         indices=[r["index"] for r in rows[4*w:4*w+4]],max_hardware_watchpoints=4)
class OriginalWriter(gdb.Breakpoint):
    def __init__(self,row):
        self.row=row
        super().__init__("*(unsigned long long *)"+row["target"],
            type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_WRITE)
        self.silent=True
    def stop(self):
        row=self.row
        index=row["index"]
        w=state["window"]
        details={"index":index,"window":w+1,"type":row["type"],"target":row["target"],
                 "pid":gdb.selected_inferior().pid}
        try:
            pid=details["pid"]
            pc=int(gdb.parse_and_eval("$pc"))
            regs={r:int(gdb.parse_and_eval("$"+r)) for r in ("x4","x10","x13","x28")}
            target=int(row["target"],16)
            after=memory_qword(target)
            instruction=gdb.execute("x/i $pc-4",to_string=True).strip()
            x28=regs["x28"]
            head=memory_qword(x28)
            off=int.from_bytes(gdb.selected_inferior().read_memory(head,4).tobytes(),"little")
            tail=head+off
            jit=memory_qword(tail+8)
            size=memory_qword(tail+16)
            count=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            bytes3=gdb.selected_inferior().read_memory(jit,3).tobytes().hex()
            tls=row["type"]=="R_X86_64_TPOFF64"
            expected_entry=0x801010014 if tls else 0x80100fb8b
            expected_bytes="488906" if tls else "4c8908"
            store_reg="x4" if tls else "x13"
            destination_reg="x10" if tls else "x4"
            expected_opcode=(r"\bstlr\s+x4,\s*\[x10\]" if tls
                             else r"\bstlr\s+x13,\s*\[x4\]")
            candidate=row["expected_candidate_plus_signed_addend"]
            details.update({
              "pc":hex(pc),"x4":hex(regs["x4"]),"x10":hex(regs["x10"]),
              "x13":hex(regs["x13"]),"x28":hex(x28),
              "written_qword":hex(after),"native_instruction":instruction,
              "jit_guest_source_entry":hex(jit),"jit_guest_source_bytes":bytes3,
              "jit_guest_source_size":size,"jit_native_instruction_count":count,
              "signed_addend":row["signed_addend"],
              "symbol":row["symbol_name"],"expected_candidate":candidate,
              "source_value_register":store_reg,"destination_register":destination_reg})
            match=re.search(r"(0x[0-9a-f]+):\s+stlr",instruction)
            ok=(state["armed"] and pid==state["pid"] and pid>0 and
                4*w<=index<4*w+4 and
                index not in [h["index"] for h in state["hits"]] and
                0xffff00000000<=pc and 0xffff00000000<=x28 and
                regs[destination_reg]==target and
                regs[store_reg]==after and
                re.search(expected_opcode,instruction)!=None and
                match is not None and pc==int(match[1],16)+4 and
                jit==expected_entry and bytes3==expected_bytes and
                size==3 and count==2 and
                (candidate is None or after==int(candidate,16)) and
                (after & (1<<63)!=0 if tls else after!=0))
            if not ok:
                state["failure"]="genuine source index native writer type-specific register or JIT mismatch"
                mark("FAIL_NATIVE_STORE",**details)
                return True
            state["hits"].append(details)
            mark("LIVE_ORIGINAL_NATIVE_STORE",**details)
            return len(state["hits"])==4*(w+1)
        except Exception as exc:
            state["failure"]=str(type(exc).__name__)+":"+str(exc)
            mark("FAIL_NATIVE_EXCEPTION",**details,error=state["failure"])
            return True
class AtOriginalLoaderBeforeRelocations(gdb.Breakpoint):
    def stop(self):
        try:
            pid=gdb.selected_inferior().pid
            assert state["pid"] is None and pid>0
            state["pid"]=pid
            for row in rows:
                addr=int(row["target"],16)
                assert memory_qword(addr)==0
                mark("BEFORE",index=row["index"],pid=pid,
                     target=row["target"],before_qword="0x0",type=row["type"])
            state["armed"]=True
            arm_window(0)
            return False
        except Exception as exc:
            state["failure"]=str(type(exc).__name__)+":"+str(exc)
            mark("FAIL_ARMING",error=state["failure"],pid=state["pid"])
            return True
AtOriginalLoaderBeforeRelocations("__SOURCE_FILE__:__SOURCE_LINE__")
end
run
'''
WINDOW=r'''python
assert state["failure"] is None, "FEX hardware original source store FAILED: "+str(state["failure"])
assert state["pid"]==gdb.selected_inferior().pid and state["pid"]>0
assert len(state["hits"])==__COUNT__, "one real FEX guest process did NOT execute the full stage window"
assert set(h["index"] for h in state["hits"])==set(range(__COUNT__)), "missing/duplicated or out-of-window native source index"
assert len({h["pid"] for h in state["hits"]})==1, "GDB FEX inferior PID changed between actual ARM64 original writer stores"
__REARM__
end
'''
LAST=r'''python
assert state["failure"] is None
assert state["armed"] and state["pid"]>0 and len(state["hits"])==40
assert set(h["index"] for h in state["hits"])==set(range(40))
assert len({h["pid"] for h in state["hits"]})==1
mark("FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT",
     pid=state["pid"],indices=sorted(h["index"] for h in state["hits"]),
     windows=10,all_147_same_guest_proven=False,
     full_original_libc_147_process_relocation_closure_proven=False,
     Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    original=original_source(triad,ledger,repo,out/"original-reverified")
    assert original["schema"]==SOURCE_SCHEMA
    assert original["stage_original_source_indices"]==list(range(40))
    assert original["new_same_guest_process_native_writers_proven"]==0
    assert original["typed_source_counts"]=={
        "R_X86_64_64":3,"R_X86_64_GLOB_DAT":22,"R_X86_64_TPOFF64":15}
    rows=[]
    for r in original["original_40_source_records"]:
        rows.append({
          "index":r["index"],"type":r["type"],
          "target":r["original_guest_target"],
          "symbol_name":r["symbol_name"],
          "signed_addend":r["original_signed_addend"],
          "candidate":r["source_symbol_address_candidate_if_non_TLS"],
          "expected_candidate_plus_signed_addend":(
            (hex((int(r["source_symbol_address_candidate_if_non_TLS"],16)+r["original_signed_addend"]) & ((1<<64)-1))
             if r["source_symbol_address_candidate_if_non_TLS"] is not None
                 and r["type"]=="R_X86_64_64" else r["source_symbol_address_candidate_if_non_TLS"])
             if r["type"]!="R_X86_64_TPOFF64" else None
          ),
        })
    assert len(rows)==40 and len({r["target"] for r in rows})==40
    header=GDB_INIT.replace("__ROWS__",repr(rows)).replace("__SOURCE_FILE__",GUEST_MAIN)
    header=header.replace("__SOURCE_LINE__",str(original["source_arming_line"]))
    script=header
    for n in range(1,11):
        source=WINDOW.replace("__COUNT__",str(n*4))
        if n<10:
            source=source.replace("__REARM__",r'''for bp in tuple(gdb.breakpoints() or ()):
    if isinstance(bp,OriginalWriter): bp.delete()
arm_window(__NEXT__)
mark("WINDOW_CHECKPOINT_SAME_PID",finished_indices=list(range(__COUNT__)),pid=state["pid"],next_window=__PRINTNEXT__)''')
            source=source.replace("__NEXT__",str(n)).replace("__PRINTNEXT__",str(n+1))
            source=source.replace("__COUNT__",str(n*4))
        else:
            source=source.replace("__REARM__","mark('FINAL_WINDOW_DONE',pid=state['pid'],count=40)")
        script+=source
        if n<10:script+="continue\n"
    script+=LAST
    assert script.count("run\n")==1
    assert script.count("\ncontinue\n")==9
    assert script.count("wp_class=gdb.WP_WRITE")==1
    assert script.count("AtOriginalLoaderBeforeRelocations(")==2
    assert script.count("arm_window(")==11
    assert script.count("KERNIX_G0_L40_A_")==1
    import ast
    parts=script.split("\npython\n")
    assert len(parts)==12
    for part in parts[1:]:
        code=part.split("\nend\n")[0]
        ast.parse(code)
    (out/GDB).write_text(script)
    data={
      "schema":SCHEMA,
      "original_libc_sha256":LIBC_SHA,
      "original_loader_sha256":LDSO_SHA,
      "stage":"G0-L40-A",
      "original_source_indices":list(range(40)),
      "type_counts":original["typed_source_counts"],
      "ten_windows":[list(range(n*4,n*4+4)) for n in range(10)],
      "gdb_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
      "first_genuine_original_relocation_guest_arm_source_line":original["source_arming_line"],
      "max_native_hardware_watchpoints_at_once":4,
      "stage_requires_one_real_FEX_inferior_PID":True,
      "prior_individual_native_writers_certified":147,
      "new_runtime_hardware_same_guest_40_certifications":0,
      "original_40_same_guest_native_writers_proven":False,
      "all_147_same_guest_native_execution_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_L40_A_SOURCE_TYPE_SPECIFIC_40_TARGET_10_WINDOW_SINGLE_PID_GDB_PYTHON_PLAN",
          "zero native claims",flush=True)
    return data
if __name__=="__main__":
    assert len(sys.argv)==5, "usage exact_original_triad canonical147_ledger repo out"
    plan(*map(Path,sys.argv[1:]))
