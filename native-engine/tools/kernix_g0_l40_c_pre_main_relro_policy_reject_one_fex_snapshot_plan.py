#!/usr/bin/env python3
"""Original GNU source C mixed 40 ELF relocation live read-only diagnostic.

This does NOT prove native store witnesses nor full GNU loader completion.
At genuine Linux ARM64 FEX initial guest entry, snapshot all 40 SHA original
libc source qwords, then at source-authentic main RELRO policy-reject boundary BEFORE _exit(177) snapshot
them in the SAME FEX inferior. Nonzero DT_JMPREL original PLT qwords and
lazy/eager JUMP_SLOT/IFUNC semantics remain explicit. This watches a real PRE-REJECTION source checkpoint. It does not bypass
RELRO, make real native source writes, execute IFUNC, or prove loader closure.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
from kernix_g0_l40_c_original_mixed_rela_jmprel80_119_source_plan import (
    run as source_run,SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT
)
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import GUEST_MAIN
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40c.authentic-gnu-80-119-one-fex-inferior-before-main-relro-reject-readonly-snapshot-plan.v1"
OUT="KERNIX-G0-L40-C-Original-GNU-40-Mixed-Relocations-One-FEX-PID-PreReject-ReadOnly-GDB-SOURCE-ONLY.json"
GDB="kernix-g0-l40-c-original-40-mixed-elf-one-fex-pid-before-relro-reject-readonly.gdb"
GDB_TPL=r'''set pagination off
set confirm off
set breakpoint pending on
set print thread-events off
handle SIGBUS nostop noprint pass
handle SIGCHLD nostop noprint pass
python
import gdb,json
rows=__ROWS__
state={"pid":None,"before":[],"after":[],"failure":None}
def mark(kind,**kv):
    gdb.write("KERNIX_G0_L40_C_PRE_REJECT_"+kind+" "+json.dumps(kv,sort_keys=True)+"\n")
def qword(addr):
    return int.from_bytes(gdb.selected_inferior().read_memory(addr,8).tobytes(),"little")
class BeforeOriginalNativeLoader(gdb.Breakpoint):
    def stop(self):
        try:
            pid=gdb.selected_inferior().pid
            assert state["pid"] is None and pid>0
            state["pid"]=pid
            for row in rows:
                addr=int(row["target"],16)
                old=qword(addr)
                if old!=int(row["original"],16):
                    raise AssertionError("GNU original old qword altered BEFORE execution at "+str(row["index"]))
                rec={"index":row["index"],"pid":pid,"type":row["type"],
                     "table":row["table"],"target":row["target"],
                     "source_old_qword":row["original"],"live_before":hex(old)}
                state["before"].append(rec)
                mark("BEFORE",**rec)
            mark("ALL_FORTY_ORIGINAL_GNU_SOURCE_QWORDS_PRISTINE_SAME_PID",
                 pid=pid,count=len(state["before"]),
                 source_rela_six=6,source_jmprel_nonzero_thirtyfour=34)
            return False
        except Exception as e:
            state["failure"]=str(type(e).__name__)+":"+str(e)
            mark("FAIL_PRISTINE_BEFORE",pid=state["pid"],error=state["failure"])
            return True
class AtRealUntrustedMainRelroRejectBoundary(gdb.Breakpoint):
    def stop(self):
        try:
            pid=gdb.selected_inferior().pid
            assert state["pid"]==pid and len(state["before"])==40
            for row in rows:
                val=qword(int(row["target"],16))
                old=int(row["original"],16)
                rec={"index":row["index"],"pid":pid,"type":row["type"],
                     "table":row["table"],"target":row["target"],
                     "source_old_qword":row["original"],
                     "live_after":hex(val),"changed_from_original":val!=old,
                     "native_hardware_store_proven_by_this_snapshot":False,
                     "IFUNC_resolver_execution_proven_by_snapshot":False,
                     "eager_or_lazy_binding_proven_by_snapshot":False}
                state["after"].append(rec)
                mark("AFTER",**rec)
            changed=[x["index"] for x in state["after"] if x["changed_from_original"]]
            unchanged=[x["index"] for x in state["after"] if not x["changed_from_original"]]
            mark("AT_MAIN_RELRO_POLICY_REJECT_READONLY_DIAGNOSTIC",
                 pid=pid,source_indices=list(range(80,120)),
                 changed_original_indices=changed,
                 unchanged_or_unresolved_original_indices=unchanged,
                 native_writer_proofs_from_this_snapshot=0,
                 all_147_same_guest_native_execution_proven=False,
                 full_GNU_original_loader_proven=False,
                 Android_Bionic_Wine_Proton_games_proven=False)
            return True
        except Exception as e:
            state["failure"]=str(type(e).__name__)+":"+str(e)
            mark("FAIL_AFTER",pid=state["pid"],error=state["failure"])
            return True
BeforeOriginalNativeLoader("__FILE__:__BEFORE_LINE__")
AtRealUntrustedMainRelroRejectBoundary("__FILE__:__AFTER_LINE__")
end
run
python
assert state["failure"] is None, "actual one FEX native source memory snapshot failed: "+str(state["failure"])
assert state["pid"] is not None and state["pid"]>0
assert len(state["before"])==40 and len(state["after"])==40, "real FEX guest did not hit original source main RELRO reject pre-exit breakpoint"
assert [x["index"] for x in state["before"]]==list(range(80,120))
assert [x["index"] for x in state["after"]]==list(range(80,120))
assert all(x["pid"]==state["pid"] for x in state["after"]+state["before"])
end
quit
'''

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L40_C_PRE_REJECT_READONLY_MIXED_ELF_SNAPSHOT_SOURCE_FAIL_CLOSED: "+msg)

def plan(triad:Path,canonical147:Path,repo:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    original=source_run(triad,canonical147,out/"regenerated-original")
    need(original["schema"]==SOURCE_SCHEMA
         and original["original_source_indices"]==list(range(80,120))
         and original["real_original_table_counts"]=={"DT_JMPREL":34,"DT_RELA":6}
         and original["new_same_guest_native_writers_proven"]==0,
         "original immutable SHA source mixed GNU source80..119, no synthetic runtime proof")
    host=repo/GUEST_MAIN
    need(host.is_file() and not host.is_symlink(),"original genuine Linux ARM64 FEX host source file")
    lines=host.read_text().splitlines()
    before=[i for i,line in enumerate(lines,1) if line.strip()=="++RealOriginalLdsoLibcCloses;"]
    after=[i-1 for i,line in enumerate(lines,1)
           if "KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT" in line]
    need(len(before)==1 and len(after)==1 and after[0]<before[0]
         and lines[after[0]-1].strip()=="std::fprintf(stderr,",
         "unique real host before GNU relocation loop and original guest main RELRO policy reject breakpoint")
    rowData=[
      {"index":r["index"],"type":r["relocation_type"],
       "table":r["original_table"],"target":r["original_guest_target"],
       "original":r["original_source_file_qword"]}
      for r in original["all_forty_source_records"]
    ]
    need(len(rowData)==40 and [x["index"] for x in rowData]==list(range(80,120)),
         "true exact GNU original source 40 qwords with original PLT nonzero")
    script=(GDB_TPL.replace("__ROWS__",repr(rowData))
            .replace("__FILE__",GUEST_MAIN)
            .replace("__BEFORE_LINE__",str(before[0]))
            .replace("__AFTER_LINE__",str(after[0])))
    need(script.count("BeforeOriginalNativeLoader(")==2
         and script.count("AtRealUntrustedMainRelroRejectBoundary(")==2
         and script.count("run\n")==1 and "KERNIX_G0_L40_C_PRE_REJECT_" in script,
         "one host GDB inferior, two real checkpoints and no invented native writer")
    import ast
    blocks=script.split("\npython\n")
    need(len(blocks)==3,"one Python block defining GDB native callbacks plus one final check")
    for block in blocks[1:]:
        ast.parse(block.split("\nend\n")[0])
    (out/GDB).write_text(script)
    doc={
      "schema":SCHEMA,"original_libc_sha256":LIBC_SHA,
      "original_ldso_sha256":LDSO_SHA,
      "original_source_indices":list(range(80,120)),
      "original_mixed_40_source_plans_sha256":hashlib.sha256(
          (out/"regenerated-original"/SOURCE_OUT).read_bytes()).hexdigest(),
      "real_host_before_relocations_source_line":before[0],
      "real_host_at_untrusted_next_main_RELRO_reject_source_line":after[0],
      "original_40_source_data":rowData,
      "gdb_script_sha256":hashlib.sha256(script.encode()).hexdigest(),
      "same_native_linux_ARM64_FEX_inferior_required":True,
      "before_and_after_source_qword_snapshot_only":True,
      "pre_main_RELRO_untrusted_address_reject_checkpoint_only":True,
      "original_guest_ExecuteThread_return_reached":False,
      "original_guest_MAIN_RELRO_policy_bypassed":False,
      "new_original_native_hardware_writer_proofs":0,
      "real_IFUNC_resolver_invocation_proven":False,
      "dynamic_JUMP_SLOT_eager_vs_lazy_binding_proven":False,
      "stage_C_forty_native_stores_one_FEX_process_proven":False,
      "all_147_same_guest_native_execution_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False}
    (out/OUT).write_text(json.dumps(doc,indent=2)+"\n")
    print("KERNIX_G0_L40_C_PRE_REJECT_ONE_REAL_FEX_PID_TWO_ORIGINAL_NATIVE_HOST_CHECKPOINTS_SOURCE_SHA_ONLY",
          "6_DT_RELA_34_NONZERO_PLT", "NO_STORE_RESOLVER_OR_LOADER_CLAIMS",flush=True)
    return doc

if __name__=="__main__":
    need(len(sys.argv)==5,"usage genuine SHA original GNU guest ELF triad canonical147 source writer ledger repository output")
    plan(*map(Path,sys.argv[1:]))
