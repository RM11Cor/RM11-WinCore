#!/usr/bin/env python3
"""Independent GNU ELF source-to-native FEX writer proof for IFUNC141..144.

Four separate real x86 guest executions share one upstream FEX ARM64 build.
This verifier does not assert a single guest process, C3 RET or Android games.
Strict original byte parity, source JIT and hardware write evidence are required.
"""
from __future__ import annotations
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA, LDSO_SHA, decode_original_libc,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import STORE

BIAS=0x804000000
FIRST=141
LAST=145
PREVIOUS=55
OUT="original-libc-IFUNC141-144-four-independent-native-hardware-writer-batch-PROOF.json"


def require(ok:bool, what:str)->None:
    if not ok:
        raise AssertionError("IFUNC141-144 INDEPENDENT HW PROOF FAIL-CLOSED: "+what)


def unique(pattern:str, log:str, label:str)->re.Match:
    matches=list(re.finditer(pattern,log,re.M))
    require(len(matches)==1,label+": expected exactly one witness")
    return matches[0]


def sha_file(path:Path, size:int, expected:str)->bytes:
    require(path.is_file() and not path.is_symlink(),str(path))
    data=path.read_bytes()
    require(len(data)==size and hashlib.sha256(data).hexdigest()==expected,str(path)+" immutable SHA256")
    return data


def independently_authenticate_source(root:Path,source:Path,prev:Path)->tuple[list[dict],dict,dict]:
    libc=sha_file(root/"lib/x86_64-linux-gnu/libc.so.6",2118168,LIBC_SHA)
    sha_file(root/"lib64/ld-linux-x86-64.so.2",235408,LDSO_SHA)
    rows=decode_original_libc(libc)
    require(len(rows)==147,"exact source 147 entries")
    prevpath=prev/"original-libc-IFUNC137-140-four-independent-native-hardware-writer-batch-PROOF.json"
    require(prevpath.is_file() and not prevpath.is_symlink(),"authentic prior four FEX guest hardware writer receipts")
    proof=json.loads(prevpath.read_text())
    require(proof["original_source_indices"]==[137,138,139,140],"four prior indices")
    require(proof["prior_independently_certified_native_hardware_target_count"]==51
            and proof["new_distinct_original_GNU_native_hardware_writer_targets"]==4
            and proof["unique_original_libc_native_hardware_writer_target_count"]==55,
            "prior independently attested 55")
    require(proof["original_source_libc_sha256"]==LIBC_SHA
            and proof["original_source_ldso_sha256"]==LDSO_SHA,"prior source SHA256")
    require(len(proof["four_independent_native_hardware_writer_receipts"])==4
            and all(r["native_source_hardware_write_independently_attested"] is True
                    for r in proof["four_independent_native_hardware_writer_receipts"]),
            "prior four individually native writer proofs")
    require(sum(len(v) for v in proof["forty_native_hardware_tamper_cases_rejected"].values())==40,
            "prior forty tamper rejections")
    require(proof["one_single_FEX_guest_process_for_all_four_writes_proven"] is False
            and proof["original_IFUNC137_140_CALL_C3_RET_native_stack_HW_READ_proven"] is False
            and proof["all_147_original_libc_RELA_JMPREL_writers_same_process_proven"] is False
            and proof["Android_Bionic_Wine_Proton_games_proven"] is False,
            "never misclaim prior one guest/RET/Android evidence")
    aggregate=json.loads((source/"original-libc-IFUNC141-144-source-batch-NOT-NATIVE-HARDWARE-PROOF.json").read_text())
    require(aggregate["exact_original_source_indices"]==[141,142,143,144],"source four indices")
    require(aggregate["certified_prior_native_writer_ledger"]==55,"source previous count")
    require(aggregate["new_independently_native_writer_attested_targets"]==0,"source itself no execution claim")
    require(aggregate["full_original_147_same_guest_relocations_proven"] is False,"source false 147")
    require(aggregate["original_source_libc_sha256"]==LIBC_SHA,"batch source identity")
    require(len(aggregate["new_source_candidates"])==4,"four source receipts")
    seen=set()
    for index in range(FIRST,LAST):
        r=rows[index]
        require(r["index"]==index and r["r_type"]==37 and r["r_sym"]==0,"exact original IFUNC")
        require(r["table"]=="DT_JMPREL" and r["table_index"]==index-86,"source ordinal")
        target=BIAS+int(r["r_offset"],16)
        resolver=BIAS+r["r_addend"]
        old=int(r["original_source_qword"],16)
        require(target not in seen,"distinct source targets")
        require(target not in {BIAS+int(q["r_offset"],16) for q in rows[:index]},"not already certified source target")
        seen.add(target)
        offset=source_offset(libc,int(r["r_offset"],16),8,6,nonexec=True)
        require(int.from_bytes(libc[offset:offset+8],"little")==old,"original immutable target qword")
        rec=aggregate["new_source_candidates"][index-FIRST]
        fname=f"original-libc-IFUNC{index}-source-only-distinct-native-write-plan"
        own=json.loads((source/(fname+".json")).read_text())
        require(own==rec,"source receipt exact byte-derived JSON")
        require(own["original_relocation_index"]==index,"source index")
        require(own["original_guest_resolver"]==hex(resolver),"source resolver")
        require(own["original_guest_target"]==hex(target),"source target")
        require(own["original_unmodified_target_qword"]==hex(old),"source original qword")
        require(own["previous_unique_native_writers_independently_certified"]==55,"source ledger")
        require(own["source_plan_only_not_real_native_FEX_execution"] is True,"source cannot certify native")
        aliases=[q["index"] for q in rows if q["r_type"]==37 and q["r_addend"]==r["r_addend"]]
        require(own["original_resolver_alias_indices"]==aliases,"source actual alias set")
        gdb=(source/(fname+".gdb")).read_bytes()
        require(gdb.count(f"watch -location *(unsigned long long *){hex(target)}".encode())==1,"source single exact GDB write watch")
    return rows,aggregate,proof


def verify_one(index:int, rows:list[dict],source:Path,native:Path,raw_override:str|None=None)->dict:
    r=rows[index]
    target=BIAS+int(r["r_offset"],16)
    resolver=BIAS+r["r_addend"]
    old=int(r["original_source_qword"],16)
    name=f"original-libc-IFUNC{index}-source-only-distinct-native-write-plan"
    gdb_src=(source/(name+".gdb")).read_bytes()
    gdb_native=native/(name+".gdb")
    require(gdb_native.is_file() and not gdb_native.is_symlink(),"native copied GDB")
    require(gdb_src==gdb_native.read_bytes(),"native exact original source watch script")
    j_native=native/(name+".json")
    require(j_native.is_file() and not j_native.is_symlink(),"native copied plan JSON")
    require((source/(name+".json")).read_bytes()==j_native.read_bytes(),"native source JSON byte identical")
    stem=f"original-libc-IFUNC{index}-four-batch-REAL-FEX-native-WRITE-only"
    p_log=native/(stem+".log")
    p_exit=native/(stem+".exit")
    require(p_log.is_file() and not p_log.is_symlink() and 200<p_log.stat().st_size<1000000,"real native FEX log")
    require(p_exit.is_file() and not p_exit.is_symlink(),"real native FEX exit")
    require(p_exit.read_text().strip()=="0","FEX hardware debugger exited zero")
    raw=p_log.read_text() if raw_override is None else raw_override
    base=f"KERNIX_G0_BATCH_IFUNC{index}_"
    arm=unique(r"^"+base+r"SOURCE_ONLY_WATCH_ARMED index=(\d+) resolver=(0x[0-9a-f]+) target=(0x[0-9a-f]+) old=(0x[0-9a-f]+) NOT_EXECUTED=1$",raw,"original armed")
    require(int(arm[1])==index and arm[2]==hex(resolver) and arm[3]==hex(target) and arm[4]==hex(old),"exact source watch index/resolver/target/old")
    watch_hits=list(re.finditer(r"^"+re.escape("Hardware watchpoint 2: -location *(unsigned long long *)"+hex(target))+r"$",raw,re.M))
    require(len(watch_hits)==2,"real GDB watchpoint appears once on arming and once on genuine native hardware write")
    watch_arm,watch_hit=watch_hits
    hit=unique(r"^"+base+r"RAW_TARGET_HARDWARE_HIT target=(0x[0-9a-f]+) pc=(0x[0-9a-f]+) guest_x4=(0x[0-9a-f]+) guest_x19=(0x[0-9a-f]+) guest_x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",raw,"actual native hardware hit")
    require(hit[1]==hex(target) and hit[4]==hex(target),"native FEX guest x19 physically targets original source qword")
    require(int(hit[2],16)>0xffff00000000 and int(hit[3],16)>BIAS and int(hit[5],16)>0xffff00000000,"real ARM64 pc, x4, source JIT state")
    jit=unique(r"^"+base+r"SOURCE_GNU_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",raw,"real original GNU guest JIT")
    require(jit[1]==hex(STORE) and int(jit[2],16)>0 and int(jit[3])>=1,"correct original x86 store JIT source")
    done=unique(r"^"+base+r"RAW_WRITER_ONLY_NO_ATTESTATION=1$",raw,"original hardware writer footer")
    new_value=unique(r"^New value = (0x[0-9a-f]+)$",raw,"genuine new hardware-write value")
    require(int(new_value[1],16)==int(hit[3],16),"new target qword exactly ARM64 x4")
    require(new_value.start()<hit.start(),"GDB watchpoint new value before our captured register marker")
    require(arm.start()<watch_arm.start()<watch_hit.start()<hit.start()<jit.start()<done.start(),"same debugger genuine arm and native hardware write chronology")
    require(re.search(r"stlr\s+x4,\s*\[x19\]",raw) is not None,"real native AArch64 stlr x4,[x19] store")
    return {"original_source_index":index,"source_resolver":hex(resolver),"original_guest_target":hex(target),"original_target_old_qword":hex(old),"real_native_AArch64_GNU_store":"stlr x4, [x19]","real_native_store_value":new_value[1],"real_guest_JIT_store":jit[1],"native_source_hardware_write_independently_attested":True,"native_same_guest_RET_hardware_read_attested":False}


def negative_cases(index:int,rows:list[dict],source:Path,native:Path)->list[str]:
    stem=f"original-libc-IFUNC{index}-four-batch-REAL-FEX-native-WRITE-only.log"
    raw=(native/stem).read_text()
    target=hex(BIAS+int(rows[index]["r_offset"],16))
    marker=f"KERNIX_G0_BATCH_IFUNC{index}_"
    changes=[
        ("wrong_index",f"SOURCE_ONLY_WATCH_ARMED index={index}",f"SOURCE_ONLY_WATCH_ARMED index={index-1}"),
        ("wrong_target",f"RAW_TARGET_HARDWARE_HIT target={target}",f"RAW_TARGET_HARDWARE_HIT target=0x1"),
        ("wrong_x19",f"guest_x19={target}",f"guest_x19=0x1"),
        ("wrong_x4",re.search(r"guest_x4=(0x[0-9a-f]+)",raw).group(0),"guest_x4=0x1"),
        ("missing_hardware_watchpoint",f"Hardware watchpoint 2: -location *(unsigned long long *){target}","Hardware watchpoint 2: NO_HARDWARE_ACCESS"),
        ("wrong_native_instruction","stlr","str_unsupported"),
        ("wrong_source_GNU_JIT","SOURCE_GNU_JIT guest_entry=","SOURCE_GNU_JIT guest_entry=0x1"),
        ("missing_write_footer",marker+"RAW_WRITER_ONLY_NO_ATTESTATION=1","FORGED_NO_FOOTER"),
        ("wrong_raw_marker",marker+"RAW_TARGET_HARDWARE_HIT",marker+"FAKE_HARDWARE_HIT"),
        ("wrong_old",f" old={hex(int(rows[index]['original_source_qword'],16))} NOT_EXECUTED=1"," old=0x1 NOT_EXECUTED=1"),
    ]
    rejected=[]
    for label,old,new in changes:
        require(old in raw,"bad negative setup "+label)
        fake=raw.replace(old,new,1)
        require(fake!=raw,"no mutation "+label)
        try:verify_one(index,rows,source,native,fake)
        except AssertionError:rejected.append(label)
        else:raise AssertionError("FAIL OPEN original IFUNC "+str(index)+" accepted forged hardware log "+label)
    require(len(rejected)==10,"ten genuine negative cases per target")
    return rejected


def run(root:Path,source:Path,native:Path,previous:Path,out:Path)->dict:
    rows,aggregate,proof=independently_authenticate_source(root,source,previous)
    receipts=[verify_one(i,rows,source,native) for i in range(FIRST,LAST)]
    rejected={str(i):negative_cases(i,rows,source,native) for i in range(FIRST,LAST)}
    require(len(receipts)==4 and len({r["original_guest_target"] for r in receipts})==4,"four unique verified real native source qwords")
    obj={
        "schema":"kernix.g0.original-gnu-libc-ifunc141-144-four-independent-FEX-AArch64-hardware-writer-watches.v1",
        "original_source_libc_sha256":LIBC_SHA,
        "original_source_ldso_sha256":LDSO_SHA,
        "original_source_indices":[141,142,143,144],
        "prior_independently_certified_native_hardware_target_count":55,
        "new_distinct_original_GNU_native_hardware_writer_targets":4,
        "unique_original_libc_native_hardware_writer_target_count":59,
        "four_independent_native_hardware_writer_receipts":receipts,
        "four_separate_FEX_guest_processes_share_one_FEX_build":True,
        "one_single_FEX_guest_process_for_all_four_writes_proven":False,
        "forty_native_hardware_tamper_cases_rejected":rejected,
        "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
        "original_IFUNC141_144_CALL_C3_RET_native_stack_HW_READ_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    require(len(rejected)==4 and sum(len(v) for v in rejected.values())==40,"40 anti-forgery cases")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(obj,indent=2)+"\n")
    return obj


if __name__=="__main__":
    require(len(sys.argv)==6,"usage: original-triad-root source-artifacts native-artifacts prior-proof output-json")
    result=run(*map(Path,sys.argv[1:]))
    print("KERNIX_G0_ORIGINAL_IFUNC141_144_FOUR_INDEPENDENT_NATIVE_HARDWARE_WRITES_ATTESTED_59_OF_147_NOT_ONE_GUEST_AND_NOT_ANDROID",result["unique_original_libc_native_hardware_writer_target_count"])
