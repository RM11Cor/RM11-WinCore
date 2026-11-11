#!/usr/bin/env python3
"""40 original GNU DT_RELA40..79 live native FEX GDB watchpoints in ONE process.

All source tuples are independently regenerated from immutable original
GNU libc+ldso SHA256, as a source-only plan. Ten GDB windows of four
hardware writepoints; rearm ONLY while the SAME inferior is stopped.
Five R_X86_64_64, one TLS TPOFF64 and thirty-four GLOB_DAT retain
different original GNU CPU register/JIT semantics. Failure must identify
individual source index and window. No native result is implied here.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l40_b_original_rela40_79_source_windows import (
    build as original_source,SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN

SCHEMA="kernix.g0.l40b.one-real-arm64-fex-process-rolling-four-hardware-original-40-source-plan.v2"
OUT="KERNIX-G0-L40-B-Rolling-Four-Watches-One-FEX-PID-Original-40-SOURCE-ONLY.json"
GDB="kernix-g0-l40-b-original-40-rolling-four-watchpoints-one-FEX-pid.gdb"

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
byindex={r["index"]:r for r in rows}
# Original source44 may be resolved before later sources, so watch it
# from the beginning. We keep four watches constantly in flight,
# retiring each witnessed source before the SAME FEX inferior resumes.
seed=[40,41,42,44]
queue=[43]+list(range(45,80))
state={"pid":None,"hits":[],"active":{},"armed_once":set(),
       "queued":list(queue),"failure":None,"ready":False}
def mark(kind,**kv):
    gdb.write("KERNIX_G0_L40_B_"+kind+" "+json.dumps(kv,sort_keys=True)+"\n")
def memory_qword(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a,8).tobytes(),"little")
def arm_one(idx):
    assert idx in byindex and idx not in state["armed_once"]
    assert len(state["active"])<4 and state["pid"]==gdb.selected_inferior().pid
    row=byindex[idx]
    cur=memory_qword(int(row["target"],16))
    if cur!=0:
        state["failure"]="next true GNU source target already written before per-index watch arming"
        mark("FAIL_EARLY_SOURCE_WRITE",index=idx,pid=state["pid"],
             target=row["target"],actual=hex(cur),
             observed_indices=[x["index"] for x in state["hits"]])
        raise AssertionError(state["failure"])
    state["active"][idx]=OriginalWriter(row)
    state["armed_once"].add(idx)
    mark("ARM_ROLLING_WATCH",index=idx,pid=state["pid"],
         target=row["target"],source_type=row["type"],
         mode=("AWATCH" if idx==44 else "WATCH"),
         maximum_concurrent_watchpoints=4,
         already_observed=[x["index"] for x in state["hits"]])
def roll_after_hit(expected_count):
    assert state["failure"] is None and state["ready"]
    assert state["pid"]==gdb.selected_inferior().pid and state["pid"]>0
    assert len(state["hits"])==expected_count
    i=state["hits"][-1]["index"]
    watcher=state["active"].pop(i)
    watcher.delete()
    replacement=None
    if state["queued"]:
        replacement=state["queued"].pop(0)
        arm_one(replacement)
    mark("REARM_AFTER_HIT",finished_index=i,pid=state["pid"],
         next_index=replacement,number_observed=expected_count,
         active_indices=sorted(state["active"]))
class OriginalWriter(gdb.Breakpoint):
    def __init__(self,row):
        self.row=row
        super().__init__("*(unsigned long long *)"+row["target"],
                         type=gdb.BP_WATCHPOINT,
                         wp_class=(gdb.WP_ACCESS if row["index"]==44 else gdb.WP_WRITE))
        self.silent=True
    def stop(self):
        row=self.row
        i=row["index"]
        details={"index":i,"type":row["type"],"target":row["target"],
                 "pid":gdb.selected_inferior().pid}
        try:
            pid=details["pid"]
            pc=int(gdb.parse_and_eval("$pc"))
            regs={r:int(gdb.parse_and_eval("$"+r)) for r in ("x4","x10","x13","x28")}
            target=int(row["target"],16)
            value=memory_qword(target)
            insn=gdb.execute("x/i $pc-4",to_string=True).strip()
            # Source44 GDB AWATCH traps genuine reads as well as stores.
            # Skip reads but never certify them as native writer evidence.
            if i==44 and re.search(r"\bstlr\s+x13,\s*\[x4\]",insn) is None:
                return False
            x28=regs["x28"]
            head=memory_qword(x28)
            off=int.from_bytes(gdb.selected_inferior().read_memory(head,4).tobytes(),"little")
            tail=head+off
            jit=memory_qword(tail+8)
            size=memory_qword(tail+16)
            count=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            op=gdb.selected_inferior().read_memory(jit,3).tobytes().hex()
            tls=row["type"]=="R_X86_64_TPOFF64"
            src_reg="x4" if tls else "x13"
            dst_reg="x10" if tls else "x4"
            expected_entry=0x801010014 if tls else 0x80100fb8b
            expected_op="488906" if tls else "4c8908"
            pat=(r"\bstlr\s+x4,\s*\[x10\]" if tls else r"\bstlr\s+x13,\s*\[x4\]")
            match=re.search(r"(0x[0-9a-f]+):\s+stlr",insn)
            candidate=row["expected_candidate_plus_signed_addend"]
            details.update({
                "pc":hex(pc),"x4":hex(regs["x4"]),"x10":hex(regs["x10"]),
                "x13":hex(regs["x13"]),"x28":hex(x28),
                "written_qword":hex(value),"native_instruction":insn,
                "jit_guest_source_entry":hex(jit),"jit_guest_source_bytes":op,
                "jit_guest_source_size":size,"jit_native_instruction_count":count,
                "signed_addend":row["signed_addend"],"symbol":row["symbol_name"],
                "expected_candidate":candidate,"source_value_register":src_reg,
                "destination_register":dst_reg,
                "observed_sequence":len(state["hits"])+1,
                "watch_slot_mode":("AWATCH" if i==44 else "WATCH")})
            ok=(state["ready"] and pid==state["pid"] and pid>0 and
                i in state["active"] and i not in [h["index"] for h in state["hits"]]
                and 0xffff00000000<=pc and 0xffff00000000<=x28
                and regs[dst_reg]==target and
                (regs[src_reg]&((1<<64)-1))==value
                and re.search(pat,insn) is not None and match is not None
                and pc==int(match[1],16)+4
                and jit==expected_entry and op==expected_op and size==3 and count==2
                and (candidate is None or value==int(candidate,16))
                and ((value&(1<<63))!=0 if tls else value!=0))
            if not ok:
                state["failure"]="native GNU source hardware store, JIT or original type mismatch"
                mark("FAIL_NATIVE_STORE",**details)
                return True
            state["hits"].append(details)
            mark("LIVE_ORIGINAL_NATIVE_STORE",**details)
            return True
        except Exception as error:
            state["failure"]=type(error).__name__+":"+str(error)
            mark("FAIL_NATIVE_EXCEPTION",**details,error=state["failure"])
            return True
class AtOriginalLoaderBeforeRelocations(gdb.Breakpoint):
    def stop(self):
        try:
            pid=gdb.selected_inferior().pid
            assert state["pid"] is None and pid>0
            state["pid"]=pid
            for row in rows:
                assert memory_qword(int(row["target"],16))==0
                mark("BEFORE",index=row["index"],pid=pid,
                     target=row["target"],before_qword="0x0",type=row["type"])
            for i in seed:arm_one(i)
            state["ready"]=True
            mark("INITIAL_FOUR_ARMED",pid=pid,indices=seed,all_zero_before=True)
            return False
        except Exception as error:
            state["failure"]=type(error).__name__+":"+str(error)
            mark("FAIL_ARMING",error=state["failure"],pid=state["pid"])
            return True
AtOriginalLoaderBeforeRelocations("__SOURCE_FILE__:__SOURCE_LINE__")
end
run
'''
CHECKPOINT=r'''python
assert state["failure"] is None, "original GNU hardware source failed: "+str(state["failure"])
assert state["pid"]==gdb.selected_inferior().pid and state["pid"]>0
assert len(state["hits"])==__COUNT__, "missing original GNU native source watchpoint store"
assert len(set(x["index"] for x in state["hits"]))==__COUNT__, "duplicate real GNU writer source"
assert all(x["pid"]==state["pid"] for x in state["hits"])
roll_after_hit(__COUNT__)
end
'''
LAST=r'''python
assert state["failure"] is None
assert state["ready"] and state["pid"]>0
assert len(state["hits"])==40
assert set(x["index"] for x in state["hits"])==set(range(40,80))
assert not state["active"] and not state["queued"]
assert len(state["armed_once"])==40
mark("FORTY_REAL_ORIGINAL_GNU_STORES_SAME_FEX_PID_RAW_NOT_INDEPENDENT",
     pid=state["pid"],indices=sorted(x["index"] for x in state["hits"]),
     observed_native_sequence=[x["index"] for x in state["hits"]],
     rolling_watch_slots_max=4,
     source44_early_awatch=True,
     all_147_same_guest_proven=False,
     full_original_libc_147_process_relocation_closure_proven=False,
     Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''

def plan(triad:Path,ledger:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    original=original_source(triad,ledger,repo,out/"original-reverified")
    assert original["schema"]==SOURCE_SCHEMA
    assert original["stage_original_source_indices"]==list(range(40,80))
    assert original["new_same_guest_process_native_writers_proven"]==0
    assert original["typed_source_counts"]=={
        "R_X86_64_64":5,"R_X86_64_GLOB_DAT":34,"R_X86_64_TPOFF64":1}
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
    for count in range(1,41):
        script+=CHECKPOINT.replace("__COUNT__",str(count))
        if count<40:script+="continue\n"
    script+=LAST
    assert script.count("run\n")==1
    assert script.count("\ncontinue\n")==39
    assert script.count('wp_class=(gdb.WP_ACCESS if row["index"]==44 else gdb.WP_WRITE)')==1
    assert script.count("AtOriginalLoaderBeforeRelocations(")==2
    assert script.count("roll_after_hit(")==41
    assert script.count("KERNIX_G0_L40_B_")==1
    import ast
    parts=script.split("\npython\n")
    assert len(parts)==43
    for part in parts[1:]:
        ast.parse(part.split("\nend\n")[0])
    (out/GDB).write_text(script)
    data={
      "schema":SCHEMA,
      "original_libc_sha256":LIBC_SHA,
      "original_loader_sha256":LDSO_SHA,
      "stage":"G0-L40-B",
      "original_source_indices":list(range(40,80)),
      "type_counts":original["typed_source_counts"],
      "ten_windows":[list(range(40+n*4,44+n*4)) for n in range(10)],
      "native_watching_strategy":"rolling-4-one-source-retired-per-real-trap",
      "initial_4_watched":[40,41,42,44],
      "rolling_watch_queue":[43]+list(range(45,80)),
      "max_simultaneous_hardware_watchpoints":4,
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
    print("KERNIX_G0_L40_B_ROLLING_FOUR_WATCHES_TYPE_SPECIFIC_40_SAME_FEX_PID_SOURCE_ONLY",
          "zero native claims",flush=True)
    return data
if __name__=="__main__":
    assert len(sys.argv)==5, "usage exact_original_triad canonical147_ledger repo out"
    plan(*map(Path,sys.argv[1:]))
