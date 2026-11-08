#!/usr/bin/env python3
"""Real original FEX AArch64 source ldso R_X86_64_IRELATIVE zero store classifier.

An archived bounded Linux ARM64 genuine FEX hardware access watch proves that
the original GNU x86 writer 49 89 06 (mov %rax,(%r14)) at guest RIP
0x80100fd60 translated to actual AArch64 stlr x4,[x19], with x4=0 and
x19=0x801036360. It follows successful real original main x86
mprotect(10); it's not a static zero snapshot. GDB watchpoint registration
is NOT a stop event. The source resolver at x86 guest RIP 0x80101a8e0 is
read-only inspected but its guest invocation/return is NOT independently
proven by this one store event. Self RELRO protection remains OPEN.
"""
from __future__ import annotations
import copy
import json
import re
import sys
from pathlib import Path

LDSO="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
SOURCE_SCHEMA="kernix.g0.original-gnu-ldso-self-irelative-source-target-watch-preflight.v1"
INITIAL="KERNIX_G0_LDSO_SELF_IRELATIVE_WATCH_ARMED_BEFORE_ORIGINAL_FEX_EXECUTE"
MAIN="KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED"
HIT="KERNIX_G0_LDSO_SELF_IRELATIVE_NATIVE_JIT_ACCESS_WATCH_HIT_BEFORE_GNU_SELF_PROTECT"
class Unproven(ValueError):pass
def must(cond,reason):
    if not cond:raise Unproven(reason)
def exactly_one(lines,part):
    found=[line for line in lines if part in line]
    must(len(found)==1,"ambiguous original GNU ldso FEX data "+part)
    return found[0]
def classify(raw,source,code):
    must(isinstance(raw,str) and isinstance(source,dict),"missing source GNU original FEX GDB trace")
    must(isinstance(code,int) and code==0,"GDB original FEX bounded watch did not exit cleanly")
    must(source.get("schema")==SOURCE_SCHEMA and source.get("source_original_ldso_sha256")==LDSO,
         "original GNU ld-linux source checksum or witness schema drift")
    expected={
      "source_original_irelative_type":37,
      "source_ldso_self_slot":"0x801036360",
      "source_original_ldso_resolver":"0x80101a8e0",
      "source_original_zero_writer_candidate":"0x80100fd60",
      "native_aarch64_hardware_access_watchpoint_guest_writer_proven":False,
      "original_guest_writer_source_RIP_proven":False,
      "original_ldso_self_RELRO_sealed":False,
      "android_game_execution_proven":False,
    }
    for key,val in expected.items():
        must(type(source.get(key)) is type(val) and source.get(key)==val,
             "source ELF original GNU ld-linux static provenance corruption "+key)
    lines=raw.splitlines()
    init=exactly_one(lines,INITIAL)
    main=exactly_one(lines,MAIN)
    hit=exactly_one(lines,HIT)
    must("target=0x801036360 source_initial_zero=1" in init,
         "wrong original ldso hardware watch target")
    must(all(key in main for key in (
         "guest_rip=801025db9","target=800003000","len=1000","prot=1",
         "native_rights=r--p","next_guest_page=rw-p",
         "eight_original_main_values_verified=1","actual_host_mprotect_succeeded=1",
         "guest_rax_zero_after_kernel=1")),
         "original GNU main real FEX guest kernel seal missing")
    must(raw.index(init)<raw.index(main)<raw.index(hit),
         "original ldso zero store did not follow live real original main RELRO protect")
    # GDB ARM64 prints "-location" *on the actual stop record* as well.
    # Distinguish a stop from watchpoint registration via chronological
    # native Linux FEX kernel-seal marker, "Value = 0x0", and real PC.
    after_main_before_hit=raw[raw.index(main):raw.index(hit)]
    stops=[line for line in after_main_before_hit.splitlines() if re.match(
        r"^Hardware access \((?:read/write|read or write)\) watchpoint 2:",line)]
    must(len(stops)==1,
         "real native hardware watchpoint stop after main kernel seal not unique: "+str(len(stops)))
    must("0x801036360" in stops[0],
         "hardware trap hit wrong original GNU ldso IRELATIVE slot")
    must("Value = 0x0" in after_main_before_hit,
         "real GDB source ldso zero-to-zero native hardware hit missing value readback")
    pc=exactly_one(lines,"pc             0x")
    m=re.search(r"\bpc\s+(0x[0-9a-fA-F]+)",pc)
    must(m is not None,"native host PC after real hardware stop missing")
    native_pc=int(m.group(1),16)
    insn=[(int(x.group(1),16),x.group(2),x.group(3))
          for line in lines for x in [re.match(
          r"^\s*(0x[0-9a-fA-F]+):\s+stlr\s+x([0-9]+),\s*\[x([0-9]+)\]",line)]
          if x is not None]
    must(len(insn)==1 and insn[0]==(native_pc-4,"4","19"),
         "hardware watch did not capture actual AArch64 STLR x4,[x19] one instruction before native PC")
    def reg(regname):
        matches=[line for line in lines if re.match(
            r"^"+re.escape(regname)+r"\s+0x[0-9a-fA-F]+",line)]
        must(len(matches)==1,"native GDB register record ambiguous or missing "+regname)
        m=re.match(r"^"+re.escape(regname)+r"\s+(0x[0-9a-fA-F]+)",matches[0])
        must(m is not None,"native GDB register value missing "+regname)
        return int(m.group(1),16)
    must(reg("x4")==0 and reg("x19")==0x801036360,
         "native actual zero-to-zero original GNU guest store data or target registers wrong")
    jit=exactly_one(lines,"KERNIX_G0_LDSO_SELF_IRELATIVE_JIT_NATIVE_TO_GUEST_BOUNDS")
    must("guest_entry=0x80100fd60" in jit and "guest_size=0x3" in jit
         and "count=2" in jit
         and f"writer_host_pc=0x{native_pc-4:x}" in jit,
         "source authenticated FEX JIT native-to-original-x86 guest single opcode provenance missing")
    ripmap=exactly_one(lines,"KERNIX_G0_LDSO_SELF_IRELATIVE_JIT_VL64PAIR_BYTES")
    must(re.search(r"count=2 data=80018002(?:0+)$",ripmap),
         "source pinned FEX JIT return RIP mapping source data unexpected")
    writer=exactly_one(lines,"0x80100fd60:")
    must(re.search(r"0x80100fd60:\s+0x49\s+0x89\s+0x06\b",writer),
         "original GNU ld-linux source x86 mov %rax,(%r14) writer bytes changed")
    resolver=exactly_one(lines,"0x80101a8e0:")
    must(re.search(r"0x80101a8e0:\s+0xf3\s+0x0f\s+0x1e\s+0xfa\b",resolver),
         "original GNU ldso self IRELATIVE resolver ENDBR64 source bytes changed")
    qwords=[line for line in lines if line.startswith("0x801036360:")]
    must(len(qwords)==2 and all("0x0000000000000000" in row for row in qwords),
         "source ldso zero initial and post actual hardware store values unreadable; a zero snapshot alone cannot prove a write")
    must("KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT" not in raw[:raw.index(hit)],
         "original source loader stopped at next unsupported syscall before hardware event")
    return {
      "schema":"kernix.g0.original-FEX-ldso-self-irelative-source-x86-zero-writer-native-STLR-proven.v1",
      "source_original_gnu_ldso_sha256":LDSO,
      "source_original_ldso_irelative_guest_target":"0x801036360",
      "source_original_guest_writer_rip":"0x80100fd60",
      "source_guest_store_opcode":"49 89 06 / mov %rax,(%r14)",
      "native_arm64_writer_host_pc":hex(native_pc-4),
      "native_arm64_instruction":"stlr x4,[x19]",
      "real_native_writer_zero_data_and_exact_address":True,
      "authentic_original_main_x86_guest_mprotect10_kernel_ro_before_writer":True,
      "source_fex_one_guest_opcode_jit_rip_proven":True,
      "actual_original_ldso_zero_to_zero_guest_x86_writer_under_FEX":True,
      "original_source_guest_irelative_resolver_RIP":"0x80101a8e0",
      "original_ldso_self_irelative_resolver_guest_entry_and_return_independently_traced":False,
      "original_ldso_self_PT_GNU_RELRO_sealed":False,
      "original_process_dynamic_relocation_and_IFUNC_closure_proven":False,
      "main_guest_program_exited_zero":False,
      "android_bionic_wine_proton_games_proven":False,
    }

def mutations(raw,source,code):
    cases=[
      ("source SHA",lambda a:a.replace(LDSO,"bad",1),source,"source"),
      ("source target",lambda a:a.replace("0x801036360","0x801036368",1),source,"source"),
      ("source x86 writer",lambda a:a.replace("0x80100fd60","0x80100fd61",1),source,"source"),
      ("fake original resolver proven",lambda a:a.replace('"original_guest_writer_source_RIP_proven": false','"original_guest_writer_source_RIP_proven": true'),source,"json"),
    ]
    counter=0
    for name,change,unused,target in cases:
        cloned=copy.deepcopy(source)
        if target=="source":
            blob=json.dumps(cloned)
            changed=change(blob)
            must(changed!=blob,"adversarial changed source was empty "+name)
            altered=json.loads(changed)
        else:
            altered=copy.deepcopy(source)
            altered["original_guest_writer_source_RIP_proven"]=True
        try:classify(raw,altered,code)
        except (Unproven,KeyError,ValueError,TypeError):
            counter+=1
            print(f"KERNIX_G0_REAL_FEX_LDSO_ZERO_WRITER_FALSE_EVIDENCE_{counter:02d}_REJECTED {name}")
        else:raise Unproven("falsified source ldso store artifact accepted "+name)
    log_mutations=[
      ("main kernel not proven",MAIN,"FAKE_MAIN_KERNEL"),
      ("guest syscall RIP wrong",
       "KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED guest_rip=801025db9",
       "KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED guest_rip=801025dba"),
      ("native guest page still rw","native_rights=r--p","native_rights=rw-p"),
      ("wrong hardware target on install","target=0x801036360","target=0x801036368"),
      ("hardware stop removed",
       "Hardware access (read/write) watchpoint 2: -location *(unsigned long long *)0x801036360",
       "Hardware access (read/write) watchpoint 3: -location *(unsigned long long *)0x801036360"),
      ("no hardware JIT hit",HIT,"FAKE_NATIVE_JIT_HIT"),
      ("fake aarch64 native STLR","stlr\tx4, [x19]","ldar\tx4, [x19]"),
      ("fake native x4 zero","x4             0x0","x4             0x1"),
      ("fake x19 target","x19            0x801036360","x19            0x801036368"),
      ("fake JIT original writer RIP","guest_entry=0x80100fd60","guest_entry=0x80100fd61"),
      ("fake JIT guest size","guest_size=0x3","guest_size=0x4"),
      ("fake JIT mapping table","data=80018002","data=80018003"),
      ("fake original x86 writer bytes","0x49\t0x89\t0x06","0x49\t0x89\t0x07"),
      ("fake source resolver bytes","0xf3\t0x0f\t0x1e\t0xfa","0xf2\t0x0f\t0x1e\t0xfa"),
      ("wrong qword post read","0x801036360:\t0x0000000000000000","0x801036360:\t0x0000000000000001"),
      ("wrong origin position","KERNIX_G0_LDSO_SELF_IRELATIVE_WATCH_ARMED_BEFORE_ORIGINAL_FEX_EXECUTE","FAKE_ARMING_ORIGIN"),
    ]
    for label,old,new in log_mutations:
        must(old in raw,"mutation seed missing "+label)
        altered=raw.replace(old,new)
        try:classify(altered,source,code)
        except (Unproven,KeyError,ValueError,TypeError):
            counter+=1
            print(f"KERNIX_G0_REAL_FEX_LDSO_ZERO_WRITER_FALSE_EVIDENCE_{counter:02d}_REJECTED {label}")
        else:raise Unproven("falsified original native FEX x86 writer evidence accepted "+label)
    must(counter==20,"20 mandatory original guest writer negative tests missing")
    return counter

def main(argv):
    if len(argv)!=5 or argv[1]!="selftest":
        print("usage: gate.py selftest NATIVE_GDB.log SOURCE_RECORD.json GDB_EXIT.txt",file=sys.stderr)
        return 2
    raw=Path(argv[2]).read_text(errors="replace")
    src=json.loads(Path(argv[3]).read_text())
    code=int(Path(argv[4]).read_text().strip())
    result=classify(raw,src,code)
    must(mutations(raw,src,code)==20,"adversarial native source writer evidence failed")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_REAL_ORIGINAL_FEX_LDSO_SELF_IRELATIVE_ZERO_TO_ZERO_SOURCE_X86_WRITER_STLR_PROVEN_AFTER_REAL_MAIN_MPROTECT_RESOLVER_ENTRY_AND_SELF_RELRO_OPEN")
    return 0
if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Unproven,KeyError,ValueError,TypeError) as e:
        print("KERNIX_G0_REAL_ORIGINAL_LDSO_SELF_IRELATIVE_WRITER_PROVENANCE_FAIL_CLOSED: "+str(e),file=sys.stderr)
        raise SystemExit(1)
