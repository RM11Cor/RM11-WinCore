#!/usr/bin/env python3
"""Independent genuine original GNU mixed 80..119 ONE FEX process read-only gate.

Attest SHA-pinned original source before/at the real UNTRUSTED main RELRO
policy rejection host boundary (0x801036000), not successful loader closure.
Thirty-nine qwords changed, one source IRELATIVE85 remains zero, which does
NOT prove the resolver was called or returned zero, nor a native write.
Reject 24 deliberately falsified per-index, PID, chronology or summary
events. No ELF security policy is weakened by this read-only probe.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_pre_main_relro_policy_reject_one_fex_snapshot_plan import (
    plan as source_plan,SCHEMA as PLAN_SCHEMA,OUT as PLAN_OUT,GDB as PLAN_GDB
)
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40c.authentic-gnu-80-119-39-changed-one-zero-same-fex-pid-before-main-relro-reject-independent-readonly.v1"
OUT="KERNIX-G0-L40-C-Original-GNU-39-Changed-85-Zero-One-FEX-PID-PreMainRELROReject-Independent-READONLY-ONLY.json"
RAW="original-gnu-mixed40-one-FEX-before-after-RAW-ONLY.json"
LOG="gnu-original-mixed40-one-FEX-pid-before-after.gdb.log"
PREFIX="KERNIX_G0_L40_C_PRE_REJECT_"
NAMES={"BEFORE":40,"AFTER":40,"ALL_FORTY_ORIGINAL_GNU_SOURCE_QWORDS_PRISTINE_SAME_PID":1,
       "AT_MAIN_RELRO_POLICY_REJECT_READONLY_DIAGNOSTIC":1}
EXPECTED_CHANGED=[i for i in range(80,120) if i!=85]

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_L40_C_READONLY_INDEPENDENT_FAIL_CLOSED: "+msg)
def read(p:Path,max_bytes=3000000):
    need(p.is_file() and not p.is_symlink(),"verified regular original GNU evidence "+str(p))
    blob=p.read_bytes()
    need(0<len(blob)<=max_bytes,"bounded immutable GNU source artifact "+str(p))
    return blob

def entries(log:str):
    events={}
    for hit in re.finditer(r"^KERNIX_G0_L40_C_PRE_REJECT_([A-Z0-9_]+) (\{[^\r\n]*\})$",log,re.M):
        k=hit[1]
        need(k in NAMES,"unrecognized, forged, failed host GDB event "+k)
        events.setdefault(k,[]).append((hit.start(),json.loads(hit[2])))
    need(set(events)==set(NAMES),"all four exact original ARM64 source snapshot marker types")
    for k,n in NAMES.items():need(len(events[k])==n,"genuine GDB 40 original source log count "+k)
    return events

def verify(log:str,source:dict):
    records=source["original_40_source_data"]
    need(len(records)==40 and [r["index"] for r in records]==list(range(80,120)),
         "original source 40 SHA tuple canonical order")
    ev=entries(log)
    before=ev["BEFORE"]; after=ev["AFTER"]
    first=ev["ALL_FORTY_ORIGINAL_GNU_SOURCE_QWORDS_PRISTINE_SAME_PID"][0]
    last=ev["AT_MAIN_RELRO_POLICY_REJECT_READONLY_DIAGNOSTIC"][0]
    pid=first[1]["pid"]
    need(type(pid)==int and pid>0 and first[1]=={
         "pid":pid,"count":40,"source_rela_six":6,"source_jmprel_nonzero_thirtyfour":34},
         "same authentic original AArch64 FEX host GDB Linux PID, source 6 RELA and 34 original PLT")
    need(all(before[i][0]<before[i+1][0] for i in range(39))
         and before[-1][0]<first[0]
         and first[0]<after[0][0]
         and all(after[i][0]<after[i+1][0] for i in range(39))
         and after[-1][0]<last[0],
         "real chronological original GNU before, FEX guest code, main-relro-reject memory after, all same PID")
    need(re.search(r"Breakpoint 1 at 0x[0-9a-f]+: file .*\.cpp, line "+str(source["real_host_before_relocations_source_line"])+r"\.",log) is not None
        and re.search(r"Breakpoint 2 at 0x[0-9a-f]+: file .*\.cpp, line "+str(source["real_host_at_untrusted_next_main_RELRO_reject_source_line"])+r"\.",log) is not None
        and re.search(r"Breakpoint 2, .*at .*\.cpp:"+str(source["real_host_at_untrusted_next_main_RELRO_reject_source_line"])+r"\b",log) is not None,
        "real original FEX ARM64 host source before and actual policy-reject GDB breakpoint hit")
    changed=[]; unchanged=[]
    for j,row in enumerate(records):
        index=row["index"]; b=before[j][1];a=after[j][1]
        expectedBefore={
          "index":index,"pid":pid,"type":row["type"],"table":row["table"],
          "target":row["target"],"source_old_qword":row["original"],
          "live_before":row["original"],
        }
        need(b==expectedBefore,"true SHA ELF original 40 guest qword pristine source at index "+str(index))
        old=int(row["original"],16)
        value=int(a["live_after"],16)
        eq=value!=old
        need(a=={
             "index":index,"pid":pid,"type":row["type"],"table":row["table"],
             "target":row["target"],"source_old_qword":row["original"],
             "live_after":hex(value),"changed_from_original":eq,
             "native_hardware_store_proven_by_this_snapshot":False,
             "IFUNC_resolver_execution_proven_by_snapshot":False,
             "eager_or_lazy_binding_proven_by_snapshot":False},
             "SHA original source qword actual same pid host-GDB read only, forbid fake writer at index "+str(index))
        (changed if eq else unchanged).append(index)
    need(changed==EXPECTED_CHANGED and unchanged==[85],
         "exactly 39 original real source qword changes and IRELATIVE85 remains zero, no inferred solver")
    need(last[1]=={
         "pid":pid,"source_indices":list(range(80,120)),
         "changed_original_indices":EXPECTED_CHANGED,
         "unchanged_or_unresolved_original_indices":[85],
         "native_writer_proofs_from_this_snapshot":0,
         "all_147_same_guest_native_execution_proven":False,
         "full_GNU_original_loader_proven":False,
         "Android_Bionic_Wine_Proton_games_proven":False},
         "terminal same-PID snapshot must neither certify IFUNC nor assert 40 source native writer stores")
    return {"pid":pid,"before":[v for _,v in before],"after":[v for _,v in after],
            "summary":last[1],"changed":changed,"unchanged":unchanged}

def falsify(log:str,kind:str,n:int,field:str,value):
    token=PREFIX+kind+" "
    matches=list(re.finditer(r"^"+re.escape(token)+r"(\{[^\r\n]*\})$",log,re.M))
    need(len(matches)==NAMES[kind] and 0<=n<len(matches),"unique original event mutation scope")
    hit=matches[n]; original=json.loads(hit[1])
    need(field in original and original[field]!=value,"negative control must change a native source witness")
    original[field]=value
    return log[:hit.start()]+token+json.dumps(original,sort_keys=True)+log[hit.end():]
def negative_controls(log:str,source:dict):
    before=[("before_pid_"+str(i),"BEFORE",i,"pid",999999) for i in (0,1,5,10,15,20,25,30,35,39)]
    after=[("after_false_change_"+str(i),"AFTER",i,"changed_from_original",False)
           for i in (0,1,2,3,4,6,10,15,20,39)]
    # Eight summary/window/IRELATIVE falsifications (some replace after).
    rest=[
       ("pristine_counts","ALL_FORTY_ORIGINAL_GNU_SOURCE_QWORDS_PRISTINE_SAME_PID",0,"count",39),
       ("pristine_pid","ALL_FORTY_ORIGINAL_GNU_SOURCE_QWORDS_PRISTINE_SAME_PID",0,"pid",999999),
       ("summary_pid","AT_MAIN_RELRO_POLICY_REJECT_READONLY_DIAGNOSTIC",0,"pid",999999),
       ("summary_forged_native_count","AT_MAIN_RELRO_POLICY_REJECT_READONLY_DIAGNOSTIC",0,"native_writer_proofs_from_this_snapshot",40),
    ]
    # Total 24 distinct controls, each independently must fail.
    mutations=before+after+rest
    need(len(mutations)==24,"exact 24 adversarial per-index and GDB one-pid controls")
    denied=[]
    for title,kind,i,field,value in mutations:
        try:verify(falsify(log,kind,i,field,value),source)
        except (AssertionError,KeyError,ValueError,TypeError):denied.append(title)
        else:raise AssertionError("FORGED_G0_L40_C_SAME_FEX_SOURCE_SNAPSHOT_PASSED "+title)
    need(len(denied)==24 and len(set(denied))==24,"all forged source snapshots rejected")
    return denied

def run(triad:Path,canonical:Path,source_artifact:Path,raw_artifact:Path,repo:Path,out:Path):
    original=source_plan(triad,canonical,repo,out/"regenerated")
    need(original["schema"]==PLAN_SCHEMA and original["original_source_indices"]==list(range(80,120))
         and original["pre_main_RELRO_untrusted_address_reject_checkpoint_only"] is True
         and original["original_guest_ExecuteThread_return_reached"] is False
         and original["original_guest_MAIN_RELRO_policy_bypassed"] is False,
         "original SHA source C genuine callback before actual RELRO rejection, not final loader")
    for name in (PLAN_OUT,PLAN_GDB):
        need(read(source_artifact/name,130000)==read(out/"regenerated"/name,130000),
             "independently regenerated source script exact source SHA & original ARM64 host line "+name)
    raw=json.loads(read(raw_artifact/RAW))
    log=read(raw_artifact/LOG,220000).decode(errors="replace")
    gdb_exit=int(read(raw_artifact/"gdb.exit",60).decode().strip())
    need(raw["schema"]=="kernix.g0.l40c.original-gnu-mixed-40-real-fex-pid-before-pre-main-relro-policy-reject-readonly-no-stores.v1"
         and raw["original_source_indices"]==list(range(80,120))
         and raw["raw_GDB_exit_code"]==gdb_exit==0
         and raw["raw_GDB_log_SHA256"]==hashlib.sha256(log.encode()).hexdigest()
         and raw["observed_40_original_GNU_before_and_after_qwords_same_pid"] is True
         and raw["native_original_per_index_hardware_store_attestations_from_this_snapshot"]==0
         and raw["pre_main_RELRO_untrusted_address_reject_checkpoint_only"] is True
         and raw["full_loader_relocation_closure_proven"] is False
         and raw["main_relro_untrusted_address_was_approved"] is False
         and raw["true_IFUNC_resolver_invocation_proven"] is False
         and raw["JUMP_SLOT_lazy_or_eager_binding_execution_proven"] is False
         and raw["forty_in_one_guest_native_writers_proven"] is False
         and raw["all_147_same_guest_native_execution_proven"] is False
         and raw["Android_Bionic_Wine_Proton_games_proven"] is False,
         "true exact original GNU no-writer GDB raw 40-source pre-RELRO rejection data")
    actual=verify(log,original)
    need(raw["one_real_linux_ARM64_FEX_guest_pid"]==actual["pid"]
         and raw["per_index_before_values"]==actual["before"]
         and raw["per_index_after_values"]==actual["after"]
         and raw["changed_at_final_FEX_guest_stop_source_indices"]==EXPECTED_CHANGED
         and raw["unchanged_or_unresolved_source_indices"]==[85],
         "source-level independent audit of all 40 unique originals and true same FEX host pid")
    denied=negative_controls(log,original)
    data={
        "schema":SCHEMA,
        "original_libc_sha256":LIBC_SHA,"original_ldso_sha256":LDSO_SHA,
        "original_source_indices":list(range(80,120)),
        "one_real_Linux_ARM64_FEX_inferior_pid_source_qword_snapshot_independently_attested":True,
        "genuine_same_linux_ARM64_FEX_inferior_pid":actual["pid"],
        "changed_original_source_qwords_indices":EXPECTED_CHANGED,
        "unchanged_original_source_qwords_indices":[85],
        "true_original_GNU_gdb_before_source_checkpoint":original["real_host_before_relocations_source_line"],
        "true_original_GNU_pre_main_RELRO_reject_checkpoint":original["real_host_at_untrusted_next_main_RELRO_reject_source_line"],
        "twentyfour_forged_source_qword_events_rejected":denied,
        "actual_native_writer_for_any_of_40_proven_by_readonly_snapshot":False,
        "original_IRELATIVE_85_resolver_invoked_or_returned_zero_proven":False,
        "original_JUMP_SLOT_binding_eager_or_lazy_proven":False,
        "stage_C_40_original_writers_together_one_FEX_pid_proven":False,
        "original_main_RELRO_policy_bypassed_or_relaxed":False,
        "all_147_original_ELF_relocations_in_single_FEX_process_proven":False,
        "full_original_ELF_dynamic_loader_relocation_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_L40_C_39_CHANGED_SOURCE_QWORDS_ONE_FEX_PID_INDEPENDENT_READONLY_AT_REJECT",
          actual["pid"],"CONTROLS_24_REJECTED_NO_NATIVE_WRITER_OR_LOADER_PROOFS",flush=True)
    return data
if __name__=="__main__":
    need(len(sys.argv)==7,"usage original_triads canonical147 sourceplan pre-relro-raw repo out")
    run(*map(Path,sys.argv[1:]))
