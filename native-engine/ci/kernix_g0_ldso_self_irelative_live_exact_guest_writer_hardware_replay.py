#!/usr/bin/env python3
"""Independent source-locked replay of actual original GNU ldso self IRELATIVE.

Hardware watch in authentic original FEX Linux ARM64 process at original
GNU ld-linux x86 R_X86_64_IRELATIVE slot after its MAIN x86 mprotect10 succeeded.
AArch64 hardware access trap: STLR x4,[x19], x4=0, x19=0x801036360,
source SHA pinned x86 store 49 89 06 -> MOV [R14],RAX, guest RIP 0x80100fd60.
JIT header/guest RIP map pin the executed *single* x86 writer instruction.

This is evidence of original dynamic-loader zero-to-zero STORE, not merely
zero-value memory read, speculative JIT compilation, or original GNU resolver
entry/return execution. Do NOT assert guest resolver RIP was executed, original
ldso self mprotect succeeded, Android or Wine/game compatibility.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

LDSO_SHA="cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
MAIN_SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
SOURCE_GUEST_STORE=0x80100fd60
SLOT=0x801036360
RESOLVER=0x80101a8e0
class Refuse(ValueError): pass
def need(condition,reason):
    if not condition:raise Refuse(reason)

def original_source(ldso:bytes):
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,
         "not the genuine immutable GNU ldso x86 source ELF")
    need(ldso[:6]==bytes.fromhex("7f454c460201") and
         struct.unpack_from("<H",ldso,18)[0]==62,
         "source GNU interpreter not ELF64 little endian AMD64")
    need(ldso[0xfd60:0xfd63]==bytes.fromhex("498906"),
         "source original zero writer not exact mov [r14],rax")
    need(ldso[0x1a8e0:0x1a8e4]==bytes.fromhex("f30f1efa"),
         "source original IFUNC resolver entry not present")
    phoff=struct.unpack_from("<Q",ldso,32)[0]
    entsize,count=struct.unpack_from("<HH",ldso,54)
    need(entsize==56 and 0<count<=64 and phoff+56*count<=len(ldso),"source PHT bounds changed")
    ph=[struct.unpack_from("<IIQQQQQQ",ldso,phoff+i*56) for i in range(count)]
    def file_offset(va,n):
        found=[p for p in ph if p[0]==1 and p[3]<=va and va+n<=p[3]+p[5] and
               p[2]+p[5]<=len(ldso)]
        need(len(found)==1,"source GNU ldso source virtual address unresolved")
        return found[0][2]+va-found[0][3]
    need(file_offset(0xfd60,3)==0xfd60 and file_offset(0x1a8e0,4)==0x1a8e0,
         "source GNU code file offset has changed")
    dynamics=[p for p in ph if p[0]==2]
    need(len(dynamics)==1,"source GNU PT_DYNAMIC count changed")
    tags={}
    d=dynamics[0]
    for i in range(d[2],d[2]+d[5],16):
        k,v=struct.unpack_from("<QQ",ldso,i)
        if k==0:break
        need(k not in tags,"duplicate original source dynamic tag")
        tags[k]=v
    need(tags.get(9)==24 and tags.get(8,0)%24==0,"source ldso DT_RELA sizes unexpected")
    rela=[struct.unpack_from("<QQq",ldso,file_offset(tags[7]+i*24,24)) for i in range(tags[8]//24)]
    need(len([x for x in rela if x==(0x36360,37,0x1a8e0)])==1,
         "source original GNU IRELATIVE reloc record missing")
    need(struct.unpack_from("<Q",ldso,file_offset(0x36360,8))[0]==0,
         "source original GNU self slot should start at zero")
    return True

def event_line(s,needle):
    arr=[line for line in s.splitlines() if needle in line]
    need(len(arr)==1,"missing or repeated live FEX hardware source evidence "+needle)
    return arr[0]

def one_native_reg(s,name):
    matches=re.findall(r"(?m)^"+re.escape(name)+r"\s+(0x[0-9a-fA-F]+)",s)
    need(len(matches)==1,"missing/duplicated original FEX native hardware register "+name)
    return int(matches[0],16)

def classify(log,source_json,ldso):
    original_source(ldso)
    need(source_json.get("schema")==
         "kernix.g0.original-gnu-ldso-self-irelative-source-target-watch-preflight.v1",
         "original source GNU IRELATIVE metadata schema")
    require={
      "source_original_ldso_sha256":LDSO_SHA,
      "source_original_irelative_type":37,
      "source_ldso_self_slot":"0x801036360",
      "source_original_ldso_resolver":"0x80101a8e0",
      "source_original_zero_writer_candidate":"0x80100fd60",
      "native_aarch64_hardware_access_watchpoint_guest_writer_proven":False,
      "original_guest_writer_source_RIP_proven":False,
      "original_ldso_self_RELRO_sealed":False,
      "android_game_execution_proven":False,
    }
    for key,value in require.items():
        need(type(source_json.get(key)) is type(value) and
             source_json.get(key)==value,"invalid source preflight state "+key)
    arm=event_line(log,"KERNIX_G0_LDSO_SELF_IRELATIVE_WATCH_ARMED_BEFORE_ORIGINAL_FEX_EXECUTE")
    main=event_line(log,"KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED")
    watch=event_line(log,"KERNIX_G0_LDSO_SELF_IRELATIVE_NATIVE_JIT_ACCESS_WATCH_HIT_BEFORE_GNU_SELF_PROTECT")
    # GDB prints this same watchpoint description TWICE: initially when
    # installing it, and again when actual hardware access stops execution.
    # Only the SECOND, live stop after main RELRO may count as native source
    # writer evidence. A registration line alone is never a writer.
    watchtext="Hardware access (read/write) watchpoint 2: -location *(unsigned long long *)0x801036360"
    matches=[m.start() for m in re.finditer(re.escape(watchtext),log)]
    need(len(matches)==2 and log.index(arm)<matches[0]<log.index(main)<matches[1]<log.index(watch),
         "watchpoint registration must precede main, true separate live hardware hit must follow")
    gdb_index=matches[1]
    for required_text in (
       "guest_rip=801025db9","target=800003000",
       "native_rights=r--p","next_guest_page=rw-p",
       "eight_original_main_values_verified=1",
       "actual_host_mprotect_succeeded=1",
       "guest_rax_zero_after_kernel=1",
       "ldso_self_IFUNC_not_yet_proven=1",
       "android_games_not_tested=1"):
        need(required_text in main,"earlier source original FEX main mprotect witness incomplete "+required_text)
    vals=event_line(log,"KERNIX_G0_LDSO_SELF_IRELATIVE_JIT_NATIVE_TO_GUEST_BOUNDS")
    m=re.search(r"guest_entry=(0x[0-9a-f]+) guest_size=(0x[0-9a-f]+) count=(\d+) data_offset=(0x[0-9a-f]+) writer_host_pc=(0x[0-9a-f]+)",vals)
    need(m is not None,"source original FEX native JIT RIP map unavailable")
    rip,glength,count,off,hostwriter=(int(a,0) for a in m.groups())
    need(rip==SOURCE_GUEST_STORE and glength==3 and count==2 and off==0x28,
         "FEX compiled native instruction block is not exact original x86 GNU zero writer")
    regs={r:one_native_reg(log,r) for r in ("pc","x0","x4","x19","x28")}
    need(regs["pc"]==hostwriter+4 and regs["x4"]==0 and regs["x19"]==SLOT,
         "original FEX native hardware STLR PC/value/destination identity failed")
    start=hostwriter-16
    need(start>=0xffff00000000 and regs["x28"]>=0xffff00000000,
         "hardware stop did not originate in expected source FEX native JIT")
    instruction={}
    for x in re.finditer(r"(?m)^[ \t]*(0x[0-9a-fA-F]+):[ \t]*([a-z][a-z0-9.]*)[ \t]*([^\r\n]*)$",log):
        pc=int(x.group(1),16)
        ins=x.group(2)
        detail=x.group(3).strip()
        if pc in (start+4,start+8,start+12,start+16):
            need(pc not in instruction,"repeated native JIT instruction")
            instruction[pc]=(ins,detail)
    need(instruction.get(start+4)==("adr","x0, "+hex(start)), "FEX JIT first adr missing")
    need(instruction.get(start+8)==("str","x0, [x28]"),"FEX JIT x28 setup missing")
    need(instruction.get(start+12)==("nop",""),"unexpected writer-prefix native instruction")
    need(instruction.get(start+16)==("stlr","x4, [x19]"),
         "source original x86 writer not observed as exact native ARM64 STLR to slot")
    table=event_line(log,"KERNIX_G0_LDSO_SELF_IRELATIVE_JIT_VL64PAIR_BYTES")
    mem=re.search(r"count=2 data=([0-9a-fA-F]+)",table)
    need(mem is not None and bytes.fromhex(mem.group(1))==bytes.fromhex("80018002")+bytes(12),
         "source FEX JIT VL64 host-to-original guest RIP map false")
    # Known pinned upstream FEX ARM64 JIT x64 fixed register array:
    # RAX->x4 and R14->x19, from original source SHA-pinned ARM64 emitter.
    need(regs["x4"]==0 and regs["x19"]==SLOT,
         "original GNU mov [r14], rax cannot match live FEX host STLR registers")
    bytes_source=event_line(log,"KERNIX_G0_LDSO_SOURCE_ZERO_WRITER_X86_RX_BYTES_BEGIN")
    need("guest_rip=0x80100fd60" in bytes_source,"wrong source GNU writer x86 guest RIP")
    live=event_line(log,"0x80100fd60:")
    need(re.search(r"0x80100fd60:\s+0x49\s+0x89\s+0x06",live) is not None,
         "live original guest x86 writer opcode differs from SHA-pinned GNU ldso")
    # The original slot is dumped BOTH at hardware-watch arming (before
    # GNU main mprotect) and immediately after the original live zero store.
    # Requiring only one would reject authentic evidence; checking both
    # ensures the access is genuinely ZERO -> ZERO rather than a new value.
    zero_records=list(re.finditer(r"(?m)^0x801036360:[ \t]+(0x[0-9a-fA-F]{16})[ \t]*$",log))
    need(len(zero_records)==2 and zero_records[0].start()<log.index(main)
         and zero_records[1].start()>log.index(watch)
         and all(m.group(1)=="0x0000000000000000" for m in zero_records),
         "authentic original GNU source self IRELATIVE zero to zero hardware target readbacks missing")
    need("KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT" not in log[:log.index(watch)],
         "self IRELATIVE watch must precede next source ldso protection")
    need("Value = 0x0" in log[gdb_index:log.index(watch)],
         "hardware target old/current value not zero")
    return {
      "schema":"kernix.g0.original-gnu-ldso-self-irelative-exact-original-x86-writer-source-FEX-hw-v1",
      "source_original_ldso_sha256":LDSO_SHA,
      "source_guest_writer_RIP":hex(rip),
      "source_guest_zero_writer_3bytes":"498906",
      "source_guest_x86_writer_opcode":"mov QWORD PTR [r14],rax",
      "source_gnu_ldso_self_irelative_guest_slot":hex(SLOT),
      "original_ldso_irelative_source_resolver_guest_entry":hex(RESOLVER),
      "native_linux_arm64_hardware_store":"stlr x4,[x19]",
      "native_FEX_x4_GUEST_RAX":hex(regs["x4"]),
      "native_FEX_x19_GUEST_R14":hex(regs["x19"]),
      "FEX_native_JIT_host_writer_PC":hex(hostwriter),
      "source_native_FEX_JIT_rip_map_pairs":[[4,0],[8,0]],
      "actual_original_GNU_ldso_zero_to_zero_store_after_main_relro_proven":True,
      "source_guest_IRELATIVE_writer_executed_RIP_proven":True,
      "source_IRELATIVE_resolver_entry_and_return_own_guest_RIP_traced":False,
      "source_ldso_self_PT_GNU_RELRO_mprotect_proven":False,
      "source_main_executable_puts_exit_zero_proven":False,
      "full_original_three_ELF_dynamic_relocation_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
      "provenance":"independently classified source-locked Linux ARM64 GDB hardware watch trap and native FEX x86 guest RIP map after original main guest syscall10 kernel RO",
    }

def negatives(log,source,ldso):
    bad=[
      ("fake source ldso ELF SHA",None,lambda d:d.update(source_original_ldso_sha256="bad")),
      ("fake source IRELATIVE type",None,lambda d:d.update(source_original_irelative_type=38)),
      ("fake source target",None,lambda d:d.update(source_ldso_self_slot="0x801036368")),
      ("fake source resolver",None,lambda d:d.update(source_original_ldso_resolver="0x80101a8e1")),
      ("fake candidate x86 guest writer",None,lambda d:d.update(source_original_zero_writer_candidate="0x80100fd61")),
      ("fake already sealed ldso",None,lambda d:d.update(original_ldso_self_RELRO_sealed=True)),
      ("fake GUI game",None,lambda d:d.update(android_game_execution_proven=True)),
    ]
    logs=[
      ("wrong main kernel protected flags","native_rights=r--p","native_rights=rw-p"),
      ("fake earlier main guest syscall",
       "KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED guest_rip=801025db9",
       "KERNIX_G0_ORIGINAL_FEX_GNU_MAIN_PT_GNU_RELRO_LIVE_GUEST_SYSCALL10_KERNEL_RO_CHILD_WRITE_DENIED guest_rip=801025dba"),
      ("wrong actual native STLR","stlr\tx4, [x19]","stur\tx4, [x19]"),
      ("wrong original GNU store source PC","guest_entry=0x80100fd60","guest_entry=0x80100fd61"),
      ("wrong native hardware x4","x4             0x0","x4             0x1"),
      ("wrong native hardware x19","x19            0x801036360","x19            0x801036368"),
      ("wrong FEX RIP map","80018002","80018003"),
      ("wrong live x86 source opcode","0x80100fd60:\t0x49\t0x89\t0x06","0x80100fd60:\t0x49\t0x89\t0x07"),
      ("fake no true kernel watch","Value = 0x0","Value = 0x1"),
      ("wrong target qword","0x801036360:\t0x0000000000000000","0x801036360:\t0x0000000000000001"),
      ("wrong original main after false source page","target=800003000","target=800004000"),
    ]
    for i,(title,_,mutate) in enumerate(bad,1):
        altered=copy.deepcopy(source);mutate(altered)
        try:classify(log,altered,ldso)
        except (Refuse,KeyError,TypeError,ValueError):
            print(f"KERNIX_G0_LDSO_SELF_IRELATIVE_FALSE_X86_GUEST_WRITER_{i:02d}_REJECTED {title}")
        else:raise Refuse("accepted false source original GNU x86 zero writer: "+title)
    for i,(title,old,new) in enumerate(logs,len(bad)+1):
        need(old in log,"adversarial mutation source log missing: "+title)
        altered=log.replace(old,new,1)
        try:classify(altered,source,ldso)
        except (Refuse,KeyError,TypeError,ValueError):
            print(f"KERNIX_G0_LDSO_SELF_IRELATIVE_FALSE_X86_GUEST_WRITER_{i:02d}_REJECTED {title}")
        else:raise Refuse("accepted mutated GNU self IRELATIVE native hardware trace: "+title)
    return len(bad)+len(logs)

def main(args):
    if len(args)!=5 or args[1]!="selftest":
        print("usage: proof.py selftest GDB.log SOURCE.json LD_SO_ELF",file=sys.stderr)
        return 2
    log=Path(args[2]).read_text(errors="replace")
    source=json.loads(Path(args[3]).read_text())
    ldso=Path(args[4]).read_bytes()
    result=classify(log,source,ldso)
    need(negatives(log,source,ldso)==18,"missing 18 corrupt source writer rejections")
    print(json.dumps(result,indent=2,sort_keys=True))
    print("KERNIX_G0_ORIGINAL_LDSO_SELF_IRELATIVE_ACTUAL_FEX_ZERO_TO_ZERO_STLR_EXACT_SOURCE_X86_RIP_PROVEN_AFTER_REAL_MAIN_MPROTECT_LDSO_SELF_RELRO_OPEN")
    return 0

if __name__=="__main__":
    try:raise SystemExit(main(sys.argv))
    except (Refuse,KeyError,ValueError,TypeError) as err:
        print("KERNIX_G0_ORIGINAL_LDSO_SELF_IRELATIVE_EXACT_X86_WRITER_FAIL_CLOSED: "+str(err),file=sys.stderr)
        raise SystemExit(1)
