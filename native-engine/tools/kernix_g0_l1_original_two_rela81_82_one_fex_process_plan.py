#!/usr/bin/env python3
"""G0-L1 original two-relocation SINGLE-process Linux ARM64 FEX source plan.

Reconstruct original GNU source81 and82 from SHA-locked true ELF and prior141.
Check canonical 147 individual receipts are certified but do not use them as
evidence of two stores in the same process. Only a new native GDB run can do so.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_original_batch81_84_source_after141 import (
    SOURCE_NAME,run as original_source_run
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN
SCHEMA="kernix.g0.l1.original-gnu-rela81-82-one-real-arm64-fex-process-plan.v1"
OUT="KERNIX-G0-L1-Original-GNU-RELA81-82-Single-FEX-Process-Source-Only.json"
GDB="kernix-g0-l1-two-real-writers-one-native-process.gdb"

def need(condition,msg):
    if not condition:
        raise AssertionError("KERNIX_G0_L1_TWO_RELA_SOURCE_FAIL_CLOSED: "+msg)
def read(path,limit=2500000):
    need(path.is_file() and not path.is_symlink(),"real regular artifact "+str(path))
    data=path.read_bytes()
    need(0<len(data)<=limit,"bounded original source evidence "+str(path))
    return data

GDB_SCRIPT=r'''set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
python
import gdb,json,re
rows=__ROW_DATA__
state={"startup_pid":None,"hits":[],"armed":False,"failure":None}
def jmark(kind, **kwargs):
    gdb.write("KERNIX_G0_L1_"+kind+" "+json.dumps(kwargs,sort_keys=True)+"\n")
def qword(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a,8).tobytes(),"little")
class OriginalWriter(gdb.Breakpoint):
    def __init__(self, row):
        self.row=row
        super().__init__("*(unsigned long long *)"+row["target"],type=gdb.BP_WATCHPOINT,wp_class=gdb.WP_WRITE)
        self.silent=True
    def stop(self):
        try:
            i=self.row["index"]
            pid=gdb.selected_inferior().pid
            pc=int(gdb.parse_and_eval("$pc"))
            x4=int(gdb.parse_and_eval("$x4"))
            x13=int(gdb.parse_and_eval("$x13"))
            x28=int(gdb.parse_and_eval("$x28"))
            target=int(self.row["target"],16)
            val=qword(target)
            inst=gdb.execute("x/i $pc-4",to_string=True).strip()
            src3=gdb.selected_inferior().read_memory(0x80100fb8b,3).tobytes().hex()
            header=qword(x28)
            off=int.from_bytes(gdb.selected_inferior().read_memory(header,4).tobytes(),"little")
            tail=header+off
            entry=qword(tail+8)
            size=qword(tail+16)
            count=int.from_bytes(gdb.selected_inferior().read_memory(tail+24,4).tobytes(),"little")
            data={"index":i,"pid":pid,"pc":hex(pc),"x4":hex(x4),"x13":hex(x13),
                  "x28":hex(x28),"target":hex(target),"value":hex(val),
                  "instruction":inst,"source_x86_3bytes":src3,
                  "FEX_guest_entry":hex(entry),"FEX_guest_size":size,"FEX_native_ops":count}
            valid=(state["armed"] and pid==state["startup_pid"] and pid>0 and
                   i not in [x["index"] for x in state["hits"]] and
                   x4==target and val==x13 and val!=0 and
                   pc>=0xffff00000000 and x28>=0xffff00000000 and
                   re.search(r"\bstlr\s+x13,\s*\[x4\]",inst)!=None and
                   src3=="4c8908" and entry==0x80100fb8b and size==3 and count==2 and
                   (self.row["candidate"] is None or val==int(self.row["candidate"],16)))
            if not valid:
                state["failure"]="single-process native hardware store or original GNU/JIT provenance mismatch"
                jmark("REJECT_NATIVE_HIT",**data)
                return True
            state["hits"].append(data)
            jmark("LIVE_HARDWARE_WRITER",**data)
            return len(state["hits"])==len(rows)
        except Exception as error:
            state["failure"]=str(type(error).__name__)+":"+str(error)
            jmark("REJECT_EXCEPTION",error=state["failure"])
            return True
class ArmBeforeOriginalLoaderWrites(gdb.Breakpoint):
    def stop(self):
        try:
            pid=gdb.selected_inferior().pid
            assert state["startup_pid"] is None and pid>0
            state["startup_pid"]=pid
            for row in rows:
                target=int(row["target"],16)
                assert qword(target)==0
                jmark("BEFORE",index=row["index"],pid=pid,target=row["target"],value="0x0")
            for row in rows:
                OriginalWriter(row)
            state["armed"]=True
            jmark("TWO_HARDWARE_WRITERS_ARMED_ONE_PID",pid=pid,indices=[r["index"] for r in rows])
            return False
        except Exception as error:
            state["failure"]=str(type(error).__name__)+":"+str(error)
            jmark("REJECT_ARMING",error=state["failure"])
            return True
ArmBeforeOriginalLoaderWrites("__HOST_FILE__:__HOST_LINE__")
end
run
python
assert state["failure"] is None, "native source trap or setup failure: "+str(state["failure"])
assert state["armed"] and state["startup_pid"] is not None,"source watches never armed"
assert [x["index"] for x in state["hits"]]==[r["index"] for r in rows], "not two actual native original stores in required order in one process"
assert len({x["pid"] for x in state["hits"]})==1 and state["hits"][0]["pid"]==state["startup_pid"],"real distinct original GNU native writer processes unexpectedly differ"
jmark("TWO_REAL_ORIGINAL_RELOCATION_WRITERS_SAME_ARM64_FEX_PID",pid=state["startup_pid"],indices=[x["index"] for x in state["hits"]],targets=[x["target"] for x in state["hits"]],values=[x["value"] for x in state["hits"]],all_147_same_guest_proven=False,Android_Bionic_Wine_Proton_games_proven=False)
end
quit
'''

def plan(triad:Path,prior141:Path,source81:Path,current147:Path,repo:Path,output:Path):
    output.mkdir(parents=True,exist_ok=True)
    regenerated=original_source_run(triad,prior141,repo,output/"regenerated")
    need(regenerated["original_source_indices"]==list(range(81,85)),"real four original ELF source records")
    need(read(source81/SOURCE_NAME)==read(output/"regenerated"/SOURCE_NAME),"original GNU source tuples re-derived from immutable SHA ELF")
    ledger=json.loads(read(current147))
    need(ledger["schema"]=="kernix.g0.original-gnu-libc-all147-independent-native-source-writers-after-dual-awatch44.v1"
         and ledger["original_relocations_total"]==147
         and ledger["previously_independently_attested_native_writer_target_count"]==147
         and ledger["remaining_requires_separate_native_hardware_evidence"]==0
         and ledger["previously_attested_original_source_indices"]==list(range(147))
         and ledger["source_original_libc_sha256"]==LIBC_SHA
         and ledger["source_original_ldso_sha256"]==LDSO_SHA
         and ledger["all_147_same_guest_native_execution_proven"] is False
         and ledger["Android_Bionic_Wine_Proton_games_proven"] is False,
         "exact current 147 individually certified source evidence, not shared process proof")
    records=regenerated["four_original_gnu_source_relocation_metadata"]
    selected=[]
    for index in (81,82):
        row=records[index-81]
        need(row["index"]==index and row["relocation_type"]=="R_X86_64_GLOB_DAT"
             and row["initial_qword"]=="0x0"
             and row["target"]==ledger["original_147_relocation_source_records"][index]["original_source_guest_target"],
             "one original ELF SHA bounded target and canonical source index "+str(index))
        selected.append({
            "index":index,"target":row["target"],"symbol":row["symbol"]["symbol_name"],
            "symbol_index":row["symbol_index"],
            "candidate":row["symbol"]["source_definition_address_candidate_if_non_TLS"],
            "relocation_type":row["relocation_type"]
        })
    need(len({r["target"] for r in selected})==2,"two separate original target locations")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"unchanged real ARM64 FEX host test driver")
    lines=[i for i,l in enumerate(host.read_text().splitlines(),1)
           if l.strip()=="++RealOriginalLdsoLibcCloses;"]
    need(len(lines)==1,"unique original host breakpoint before GNU loader store loop")
    script=GDB_SCRIPT.replace("__ROW_DATA__",repr(selected)).replace("__HOST_FILE__",GUEST_MAIN).replace("__HOST_LINE__",str(lines[0]))
    need(script.count('ArmBeforeOriginalLoaderWrites("')==1 and
         script.count("class OriginalWriter(")==1 and "wp_class=gdb.WP_WRITE" in script,
         "exact actual GDB Python two native hardware watchpoint probes")
    (output/GDB).write_text(script)
    record={"schema":SCHEMA,"original_source_libc_sha256":LIBC_SHA,
            "original_source_ldso_sha256":LDSO_SHA,
            "original_source_indices":[81,82],"source_tuples":selected,
            "host_before_original_loader_write_line":lines[0],
            "gdb_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
            "individual_native_source_writers_already_certified":147,
            "new_same_process_native_hardware_writers_proven":0,
            "all_147_same_guest_native_execution_proven":False,
            "Android_Bionic_Wine_Proton_games_proven":False}
    (output/OUT).write_text(json.dumps(record,indent=2)+"\n")
    print("KERNIX_G0_L1_TWO_GENUINE_ORIGINAL_RELOCATION_SOURCE_WATCHES_ONE_FEX_PROCESS_PLAN_NO_RUNTIME_PROOF",record["source_tuples"])
    return record

if __name__=="__main__":
    need(len(sys.argv)==7,"usage genuine-triad prior141 source81..84 current147 repo output")
    plan(*map(Path,sys.argv[1:]))
