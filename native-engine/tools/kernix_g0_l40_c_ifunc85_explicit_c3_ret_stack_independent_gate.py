#!/usr/bin/env python3
"""Independent real ARM64 FEX hardware READ of original GNU IFUNC85 C3 RET.

The native watch must be armed at actual resolver JIT entry over the live
guest stack return slot; a read must then map exactly to original x86 RET
0x8040c860d before caller 0x80100fd5c and real zero STLR. No fake/mocked
guest instruction, no Android or full loader closure claims.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_l40_c_ifunc85_explicit_c3_ret_stack_hw_plan import (
    plan as make_source, SCHEMA as PLAN_SCHEMA, GDB as GDB_SCRIPT,
    OUT as PLAN_OUT, RET_ADDR,
)
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_independent_gate import (
    verify as prior_verify, negatives as prior_negative,
)
from kernix_g0_l40_c_ifunc85_resolver_entry_caller_after_five_source_plan import OUT as PRIOR_OUT
from kernix_g0_l40_c_irelative85_after_five_same_fex_awatch_plan import OUT as SIX_OUT

SCHEMA="kernix.g0.l40c.original-gnu-ifunc85-exact-c3-ret-stack-native-read-one-fex-pid-independent.v1"
OUT="KERNIX-G0-C-IFUNC85-Exact-C3-RET-HW-Stack-Read-Resolver-Writer-Same-FEX-PID.json"
LOG="original-gnu-ifunc85-exact-c3-ret-native-hardware-stack-read-one-FEX-pid.gdb.log"
ARM="IFUNC85_SOURCE_C3_RET_STACK_HW_RWATCH_ARMED"
READ="IFUNC85_ORIGINAL_C3_RET_NATIVE_STACK_HW_READ"
FINAL="IFUNC85_EXACT_C3_RET_HW_READ_AND_SIX_NATIVE_WRITERS_ONE_FEX_PID"
ENTRY="IFUNC85_RESOLVER_JIT_ENTRY_HW"
CALLER="IFUNC85_CALLER_JIT_RETURN_SITE_HW"
WRITE="IFUNC85_TRUE_NATIVE_ZERO_TO_ZERO_STORE"
PREFIX="KERNIX_G0_L40_C_"
PAT=re.compile(r"^KERNIX_G0_L40_C_([A-Z0-9_]+) (\{[^\r\n]*\})$",re.M)

def need(ok,msg):
    if not ok: raise AssertionError("KERNIX_G0_C_IFUNC85_TRUE_C3_RET_READ_FAIL_CLOSED: "+msg)
def read(path,limit=3000000):
    need(path.is_file() and not path.is_symlink(),"real source and FEX hardware file "+str(path))
    blob=path.read_bytes()
    need(0<len(blob)<=limit,"bounded native evidence "+str(path))
    return blob
def events(log):
    e={}
    for m in PAT.finditer(log):
        e.setdefault(m[1],[]).append((m.start(),json.loads(m[2])))
    for k in (ARM,READ,FINAL,ENTRY,CALLER,WRITE):
        need(len(e.get(k,[]))==1,"unique original GNU hardware return chain "+k)
    for k in ("IFUNC85_RET_READ_REJECT_EXCEPTION","IFUNC85_JIT_SCAN_BOUNDED_REJECT"):
        need(k not in e,"no native FEX hardware source RET error "+k)
    need(len(e.get("IFUNC85_RET_STACK_ACCESS_UNCLASSIFIED",[]))<=15,
         "bounded genuine hardware read access for C3 source")
    return e

def verify(log,src):
    need(src["schema"]==PLAN_SCHEMA and
         src["source_original_guest_C3_RET_RIP"]==hex(RET_ADDR)
         and src["source_original_guest_C3_RET_byte"]=="c3"
         and src["original_GNU_guest_indirect_CALL"]=="0x80100fd5a"
         and src["original_GNU_caller_return_guest_RIP"]=="0x80100fd5c"
         and src["original_GNU_source_writer"]=="0x80100fd60"
         and src["source_original_source85_target"]=="0x8042014c8",
         "source SHA original GNU CALL C3 RET return store exact guest RIP")
    pid,entry,caller=prior_verify(log,src["prior_gate_source"])
    ev=events(log)
    entrypos=ev[ENTRY][0][0]
    armpos,arm=ev[ARM][0]
    readpos,reading=ev[READ][0]
    callerpos=ev[CALLER][0][0]
    writepos=ev[WRITE][0][0]
    finalpos,final=ev[FINAL][0]
    need(entrypos<armpos<readpos<callerpos<writepos<finalpos,
         "actual original FEX resolver entry followed by guest C3 hardware read then source caller and native zero store")
    for pos,x in ev.get("IFUNC85_RET_STACK_ACCESS_UNCLASSIFIED",[]):
        need(armpos<pos<readpos and x["pid"]==pid,
             "read-only hardware access must occur before confirmed original C3 RET")
    need(arm=={
        "pid":pid,"stack_slot":entry["guest_rsp"],
        "expected_return":"0x80100fd5c",
        "source_guest_C3_RET":hex(RET_ADDR),
        "original_ret_hardware_read_proven_yet":False,
    },"dynamic authentic guest RSP return slot source watch arming")
    expected_keys={
        "pid","read_ordinal","slot","return_value","pc","native_instruction",
        "guest_rsp_after_read","guest_rax","FEX_guest_entry",
        "FEX_guest_size","FEX_native_ops","source_original_guest_ret_byte",
    }
    need(set(reading)==expected_keys
         and type(reading["pid"]) is int and reading["pid"]==pid
         and type(reading["read_ordinal"]) is int
         and reading["read_ordinal"]==len(ev.get("IFUNC85_RET_STACK_ACCESS_UNCLASSIFIED",[]))+1
         and 1<=reading["read_ordinal"]<=16
         and reading["slot"]==entry["guest_rsp"]
         and reading["return_value"]=="0x80100fd5c"
         and reading["guest_rax"]=="0x0"
         and reading["source_original_guest_ret_byte"]=="c3"
         and reading["FEX_guest_entry"]==hex(RET_ADDR)
         and type(reading["FEX_guest_size"]) is int and reading["FEX_guest_size"]==1
         and type(reading["FEX_native_ops"]) is int and 1<=reading["FEX_native_ops"]<=128
         and int(reading["guest_rsp_after_read"],16) in
             (int(entry["guest_rsp"],16),int(entry["guest_rsp"],16)+8)
         and int(reading["pc"],16)>=0xffff00000000
         and re.search(r"\b(?:ldr|ldar|ldur|ldp)\s+",reading["native_instruction"],re.I) is not None,
         "native x86 C3 RET JIT mapped hardware stack READ, original return address and live guest registers")
    need(final=={
        "pid":pid,
        "native_original_C3_RET_source_mapped_hardware_stack_read":True,
        "original_source85_zero_to_zero_store":True,
        "original_source85_resolver_and_caller_JIT_observed":True,
        "stage_C_all_40_original_GNU_relocations_proven":False,
        "full_original_dynamic_loader_closure_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    },"full source C3 RET chain only, other loader gates closed")
    return pid,reading,ev

def replace_event(log,kind,num,key,bad):
    found=[m for m in PAT.finditer(log) if m[1]==kind]
    need(num<len(found),"actual original FEX GDB log event present")
    m=found[num];event=json.loads(m[2])
    need(key in event and event[key]!=bad,"each fake must change source evidence")
    event[key]=bad
    return log[:m.start()]+PREFIX+kind+" "+json.dumps(event,sort_keys=True)+log[m.end():]

def forged_controls(log,src):
    cases=[
        ("watch_pid",ARM,0,"pid",999999),
        ("watch_slot",ARM,0,"stack_slot","0x1"),
        ("watch_return",ARM,0,"expected_return","0x1"),
        ("watch_ret_opcode",ARM,0,"source_guest_C3_RET","0x1"),
        ("stack_read_pid",READ,0,"pid",999999),
        ("stack_read_slot",READ,0,"slot","0x1"),
        ("stack_read_return",READ,0,"return_value","0x1"),
        ("stack_read_source",READ,0,"FEX_guest_entry","0x1"),
        ("stack_read_guest_size",READ,0,"FEX_guest_size",3),
        ("stack_read_byte",READ,0,"source_original_guest_ret_byte","90"),
        ("stack_read_pc",READ,0,"pc","0x1"),
        ("stack_read_rax",READ,0,"guest_rax","0x1"),
        ("stack_read_rsp",READ,0,"guest_rsp_after_read","0x1"),
        ("stack_read_native_inst",READ,0,"native_instruction","0x0: str x0, [x8]"),
        ("fake_final_pid",FINAL,0,"pid",999999),
        ("fake_final_ret",FINAL,0,"native_original_C3_RET_source_mapped_hardware_stack_read",False),
    ]
    need(len(cases)==16,"16 counterfeit native original GNU C3 RET stack read controls")
    denied=[]
    for name,kind,num,key,bad in cases:
        try:verify(replace_event(log,kind,num,key,bad),src)
        except (AssertionError,KeyError,ValueError,TypeError):denied.append(name)
        else:raise AssertionError("FORGED_ACTUAL_GNU_IFUNC85_C3_RET_STACK_READ_ACCEPTED "+name)
    need(len(denied)==16 and len(set(denied))==16,"all sixteen fake original C3 RET native read controls rejected")
    return denied

def run(triad:Path,ledger:Path,repo:Path,rawdir:Path,out:Path):
    source=make_source(triad,ledger,repo,out/"regenerated")
    gdb=read(out/"regenerated"/GDB_SCRIPT,180000)
    need(hashlib.sha256(gdb).hexdigest()==source["generated_native_GDB_script_sha256"],
         "true regenerated SHA original ELF source GDB stack read hardware proof script")
    log=read(rawdir/LOG,300000).decode(errors="replace")
    rc=int(read(rawdir/"gdb.exit",60).decode().strip())
    need(rc==0,"actual native Linux ARM64 FEX exact original C3 RET hardware read")
    prior_folder=out/"regenerated"/"previous"
    prior=json.loads(read(prior_folder/PRIOR_OUT))
    six_folder=prior_folder/"six-source"
    six=json.loads(read(six_folder/SIX_OUT))
    six["first_five_source_plan"]=json.loads(read(
        six_folder/"five-source"/"KERNIX-G0-C-Original-GLOB_DAT80-84-Five-Rolling-One-FEX-PID-SOURCE-ONLY.json"))
    prior["six_gate_source"]=six
    source["prior_gate_source"]=prior
    pid,reading,_=verify(log,source)
    denied=forged_controls(log,source)
    prior_denied=prior_negative(log,prior)
    need(len(denied)==16 and len(prior_denied)==18,
         "16 new RET + 18 prior JIT original same-process false native evidence rejections")
    result={
        "schema":SCHEMA,
        "real_linux_ARM64_FEX_inferior_pid":pid,
        "source_indices_real_native_writer_events_in_same_pid":[80,81,82,83,84,85],
        "source_IFUNC85_original_C3_RET_read_hardware_observed":True,
        "source_IFUNC85_original_ret_guest_RIP":hex(RET_ADDR),
        "source_IFUNC85_original_ret_stack_slot":reading["slot"],
        "source_IFUNC85_original_ret_native_ldr":reading["native_instruction"],
        "source_IFUNC85_guest_return_value":"0x80100fd5c",
        "source_IFUNC85_resolver_entry_caller_site_and_zero_STLR_same_pid":True,
        "sixteen_forged_C3_RET_hardware_reads_rejected":denied,
        "eighteen_forged_resolver_caller_JIT_events_rejected":prior_denied,
        "genuine_original_native_FEX_GDB_log_sha256":hashlib.sha256(log.encode()).hexdigest(),
        "all_original_IFUNC85_resolver_body_semantics_proven":False,
        "stage_C_40_original_GNU_relocations_one_PID_proven":False,
        "original_GNU_main_ldso_RELRO_sealing_proven":False,
        "all_147_original_dynamic_relocations_one_FEX_process_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/OUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_C_ORIGINAL_IFUNC85_EXACT_C3_RET_NATIVE_GUEST_STACK_READ_CALLER_ZERO_STORE_ONE_PID_PROVEN",
          pid,"16_FORGED_RET_REJECTED_NO_FULL_LOADER")
    return result

if __name__=="__main__":
    need(len(sys.argv)==6,"usage source_original_triad canonical147 ledger repo raw_native evidence_out")
    run(*map(Path,sys.argv[1:]))
