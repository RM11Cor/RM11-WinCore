#!/usr/bin/env python3
"""Independent audit of original GNU GLOB_DAT source80..84 rolling hardware writes.

Reaudit the first FOUR writes independently using their exact existing gate.
Only then attest a fifth native STLR store inside the SAME real ARM64 FEX PID.
No IFUNC85, JMPREL, main RELRO sealing, Wine, Android or game execution claim.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path
from kernix_g0_l40_c_first_five_rolling_original_fex_plan import (
    plan as source_plan, SCHEMA as PLAN_SCHEMA, GDB as GDB_SCRIPT,
)
from kernix_g0_l40_c_first_four_original_writers_independent_gate import (
    audit as first_four_audit, negative_controls as first_four_controls,
)
from kernix_g0_l40_c_original_globdat80_83_real_fex_four_writers_plan import (
    SCHEMA as FIRST_FOUR_SCHEMA,
)

SCHEMA = "kernix.g0.l40c.true-original-gnu-globdat80-84-five-in-one-fex-pid-native-stores-independent.v1"
OUT = "KERNIX-G0-C-Original-GNU-GLOB_DAT80-84-Five-Real-Writers-Independent-NOT-C40.json"
RAW_LOG = "gnu-original-globdat80-84-five-one-FEX-pid.gdb.log"
ARM = "FIFTH_GLOB_DAT84_ARMED_AFTER_FOUR_IN_SAME_PID"
HIT = "LIVE_HARDWARE_WRITER"
FINAL = "FIVE_REAL_ORIGINAL_GLOB_DAT_80_84_WRITERS_SAME_ARM64_FEX_PID"
PREFIX = "KERNIX_G0_L40_C_"
PAT = re.compile(r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$", re.M)

def need(condition, msg):
    if not condition:
        raise AssertionError("KERNIX_G0_C_FIFTH_GNU_NATIVE_INDEPENDENT_FAIL_CLOSED: " + msg)

def read(p: Path, limit=2_000_000):
    need(p.is_file() and not p.is_symlink(), "regular original GNU FEX evidence " + str(p))
    blob = p.read_bytes()
    need(0 < len(blob) <= limit, "bounded original evidence " + str(p))
    return blob

def evidence(log: str):
    events = {}
    for match in PAT.finditer(log):
        name = match[1]
        need(name in {
            "BEFORE", "FOUR_HARDWARE_WRITERS_ARMED_ONE_PID",
            "FOUR_REAL_ORIGINAL_GLOB_DAT_80_83_WRITERS_SAME_ARM64_FEX_PID",
            ARM, HIT, FINAL,
        }, "unknown/rejected native GDB record " + name)
        events.setdefault(name, []).append((match.start(), json.loads(match[2])))
    counts = {
        "BEFORE":4,
        "FOUR_HARDWARE_WRITERS_ARMED_ONE_PID":1,
        "FOUR_REAL_ORIGINAL_GLOB_DAT_80_83_WRITERS_SAME_ARM64_FEX_PID":1,
        ARM:1, HIT:5, FINAL:1,
    }
    need(set(events) == set(counts), "all exact original GNU five writer marker classes")
    for name, count in counts.items():
        need(len(events[name]) == count, "original native GDB "+name+" event count")
    return events

def verify(log: str, source: dict):
    need(source["schema"] == PLAN_SCHEMA and source["source_indices"] == [80,81,82,83,84],
         "original SHA ELF five GLOB_DAT source plan")
    events = evidence(log)
    arm_position, arm = events[ARM][0]
    first_end = events["FOUR_REAL_ORIGINAL_GLOB_DAT_80_83_WRITERS_SAME_ARM64_FEX_PID"][0][0]
    hits = events[HIT]
    final_position, final = events[FINAL][0]
    need(hits[3][0] < first_end < arm_position < hits[4][0] < final_position,
         "hardware watches rolled only after actual first four original native stores")
    first_part = log[:arm_position]
    first_source = {
        "schema": FIRST_FOUR_SCHEMA,
        "source_indices": [80,81,82,83],
        "four_genuine_original_ELF_GLOB_DAT_source_tuples":source["first_four_rows"],
    }
    first = first_four_audit(first_part, first_source)
    pid = first["pid"]
    fifth = source["fifth_original_GNU_GLOB_DAT_source_row"]
    need(type(pid) is int and pid > 0 and fifth["index"] == 84,
         "authentic fifth original ELF row and same live PID")
    need(arm == {
        "pid":pid,"index":84,"target":fifth["target"],"pristine":"0x0",
        "first_four_indices":[80,81,82,83],
        "only_one_watch_armed_after_four":True,
    }, "five-in-one-PID source84 was initially zero before fifth watch")
    hit = hits[4][1]
    need(set(hit)=={
         "index","pid","pc","x4","x13","x28","target","value",
         "instruction","source_x86_3bytes","FEX_guest_entry",
         "FEX_guest_size","FEX_native_ops",
    }, "exact original fifth GNU ARM64 hardware store fields")
    need(hit["index"] == 84 and type(hit["pid"]) is int and hit["pid"]==pid
         and hit["target"]==fifth["target"]
         and hit["value"]==fifth["candidate"]
         and hit["x4"]==fifth["target"]
         and hit["x13"]==fifth["candidate"]
         and int(hit["pc"],16)>=0xffff00000000
         and int(hit["x28"],16)>=0xffff00000000
         and re.search(r"\bstlr\s+x13,\s*\[x4\]",hit["instruction"]) is not None
         and hit["source_x86_3bytes"]=="4c8908"
         and hit["FEX_guest_entry"]=="0x80100fb8b"
         and type(hit["FEX_guest_size"]) is int and hit["FEX_guest_size"]==3
         and type(hit["FEX_native_ops"]) is int and hit["FEX_native_ops"]==2,
         "real source84 guest-linked ARM64 STLR hardware fifth write")
    need(final == {
        "pid":pid,"indices":[80,81,82,83,84],
        "targets":[x["target"] for x in source["first_four_rows"]+[fifth]],
        "values":[x["candidate"] for x in source["first_four_rows"]+[fifth]],
        "source85_IRELATIVE_proven":False,
        "all_40_stage_C_proven":False,
        "all_147_same_guest_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }, "true fifth FEX writer without full loader or Android claim")
    return {"pid":pid,"fifth_hit":hit,"first_four":first}

def falsify(log: str, kind: str, occurrence: int, field: str, bad):
    matches=[m for m in PAT.finditer(log) if m[1]==kind]
    need(len(matches) >= occurrence+1, "adversarial original GDB source marker exists")
    m=matches[occurrence]
    record=json.loads(m[2])
    need(field in record and record[field]!=bad, "mutation must change original native event")
    record[field]=bad
    return log[:m.start()] + PREFIX+kind+" "+json.dumps(record,sort_keys=True) + log[m.end():]

def negative_controls(log: str, source: dict):
    probes=[
        ("armed_pid",ARM,0,"pid",999999),
        ("armed_index",ARM,0,"index",85),
        ("armed_target",ARM,0,"target","0x1"),
        ("armed_pristine",ARM,0,"pristine","0x1"),
        ("armed_watch_not_recycled",ARM,0,"only_one_watch_armed_after_four",False),
        ("writer_index",HIT,4,"index",83),
        ("writer_pid",HIT,4,"pid",999999),
        ("writer_target",HIT,4,"target","0x1"),
        ("writer_register_x4",HIT,4,"x4","0x1"),
        ("writer_register_x13",HIT,4,"x13","0x1"),
        ("writer_value",HIT,4,"value","0x1"),
        ("writer_native_ops",HIT,4,"FEX_native_ops",99),
        ("writer_guest_bytes",HIT,4,"source_x86_3bytes","909090"),
        ("writer_jit_guest_entry",HIT,4,"FEX_guest_entry","0x1"),
        ("final_pid",FINAL,0,"pid",999999),
        ("forged_C40_claim",FINAL,0,"all_40_stage_C_proven",True),
    ]
    need(len(probes)==16, "sixteen genuine fifth native writer adversarial tests")
    rejected=[]
    for title,kind,index,field,bad in probes:
        try:verify(falsify(log,kind,index,field,bad),source)
        except (AssertionError,KeyError,ValueError,TypeError):rejected.append(title)
        else:raise AssertionError("FORGED_GNU_GLOB_DAT84_FIFTH_HARDWARE_TRACE_ACCEPTED "+title)
    need(len(rejected)==16 and len(set(rejected))==16,
         "all sixteen genuine native fifth writer spoof attempts rejected")
    return rejected

def run(triad:Path,ledger:Path,repo:Path,raw_dir:Path,out:Path):
    source=source_plan(triad,ledger,repo,out/"regenerated")
    script=read(out/"regenerated"/GDB_SCRIPT,130000)
    need(hashlib.sha256(script).hexdigest()==source["native_gdb_rolling_script_sha256"],
         "exact generated original ARM64 GDB one PID rolling script SHA")
    log=read(raw_dir/RAW_LOG,250000).decode(errors="replace")
    rc=int(read(raw_dir/"gdb.exit",60).decode().strip())
    need(rc==0,"actual one FEX PID native GDB four then fifth must exit zero")
    observed=verify(log,source)
    first_source={
        "schema": FIRST_FOUR_SCHEMA,
        "source_indices":[80,81,82,83],
        "four_genuine_original_ELF_GLOB_DAT_source_tuples":source["first_four_rows"],
    }
    first_logs=log[:evidence(log)[ARM][0][0]]
    first_denied=first_four_controls(first_logs,first_source)
    fifth_denied=negative_controls(log,source)
    need(len(first_denied)==28 and len(fifth_denied)==16,
         "44 total independent source native hardware forgery controls")
    report={
       "schema":SCHEMA,
       "source_indices_with_genuine_native_hardware_writers_in_one_FEX_pid":[80,81,82,83,84],
       "native_arm64_FEX_inferior_pid":observed["pid"],
       "five_source_writers_independently_verified":5,
       "four_previous_writer_forgery_events_rejected":first_denied,
       "fifth_writer_forgery_events_rejected":fifth_denied,
       "native_trace_sha256":hashlib.sha256(log.encode()).hexdigest(),
       "source85_IFUNC_resolver_or_zero_to_zero_store_proven":False,
       "stage_C_forty_source_native_writers_one_pid_proven":False,
       "all_147_one_guest_loader_relocation_closure_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(report,indent=2)+"\n")
    print("KERNIX_G0_C_REAL_ORIGINAL_GNU_80_84_FIVE_NATIVE_STLR_WRITERS_ONE_FEX_PID_PASS",
          observed["pid"],"44_INDEPENDENT_FORGED_TRACES_REJECTED_NO_STAGE_C_CLOSURE")
    return report

if __name__=="__main__":
    need(len(sys.argv)==6,"usage genuine_GNU_triad canonical147 repo_root raw_fex_dir output")
    run(*map(Path,sys.argv[1:]))
