#!/usr/bin/env python3
"""Independently authenticate original GNU libc IFUNC85 ZERO-to-ZERO write.

A GDB awatch is READ-or-WRITE. Certification requires original SHA-locked
DT_RELA source 85, exact initial/live zero, after-arm native access trap,
AArch64 STLR x4,[x19] with x4=0 and x19=exact target, SAME guest JIT header
mapping to original GNU x86 ldso STORE 49 89 06, and 12 counterfeit rejections.

This gate NEVER proves one-guest all 147, original guest CALL/C3 RET stack
hardware read, Android, Wine, Vulkan, APK, or a running PC game.
"""
from __future__ import annotations
import hashlib,json,re,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import (
    LIBC_SHA,LDSO_SHA,decode_original_libc,classify,
)
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import (
    CALL,STORE,LIBC_BIAS,LDSO_BIAS,
)
BASE="original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS"
SOURCE="original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF"
PRIOR="original-libc-IFUNC145-146-two-independent-native-hardware-writer-batch-PROOF.json"
TARGET="0x8042014c8"


def need(cond:bool,what:str)->None:
    if not cond: raise AssertionError("KERNIX original IFUNC85 independent G0 WRITER FAIL CLOSED: "+what)


def obj(p:Path)->dict:
    need(p.is_file() and not p.is_symlink(),"JSON "+p.name)
    data=json.loads(p.read_text())
    need(isinstance(data,dict),"JSON object "+p.name)
    return data


def sole(pattern:str,s:str,label:str):
    matches=list(re.finditer(pattern,s,re.M))
    need(len(matches)==1,"unique "+label+" ("+str(len(matches))+")")
    return matches[0]


def original_sha_source(triad:Path,source:Path,prev:Path):
    libp=triad/"lib/x86_64-linux-gnu/libc.so.6"
    ldp=triad/"lib64/ld-linux-x86-64.so.2"
    need(libp.is_file() and ldp.is_file() and not libp.is_symlink() and not ldp.is_symlink(),"real pinned GNU source")
    libc,ldso=libp.read_bytes(),ldp.read_bytes()
    need(len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA,"exact original libc SHA")
    need(len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA,"exact original ldso SHA")
    rows=decode_original_libc(libc)
    need(classify(rows)["original_total_RELA_and_JMPREL"]==147,"all original source relocations")
    r=rows[85]
    need((r["index"],r["table"],r["table_index"],r["r_type"],r["r_sym"],r["r_offset"],r["r_addend"],r["source_guest_target"],r["original_source_qword"]) ==
         (85,"DT_RELA",85,37,0,"0x2014c8",0xc8570,TARGET,"0x0"),"exact original IFUNC85 DT_RELA zero target resolver")
    for code,expected,dat,bias in (
            (0xc860b,"31c0",libc,0),
            (0xc860d,"c3",libc,0),
            (CALL,"ffd0",ldso,LDSO_BIAS),
            (STORE,"498906",ldso,LDSO_BIAS)):
        raw=bytes.fromhex(expected)
        off=source_offset(dat,code-bias,len(raw),5)
        need(dat[off:off+len(raw)]==raw,"original x86 GNU resolver and ldso store opcodes")
    off=source_offset(libc,0x2014c8,8,6,nonexec=True)
    need(int.from_bytes(libc[off:off+8],"little")==0,"immutable zero original target QWORD")
    p=obj(source/(SOURCE+".json"))
    need(p["original_guest_target"]==TARGET and p["original_relocation_index"]==85
         and p["original_table"]=="DT_RELA" and p["original_table_ordinal"]==85
         and p["original_guest_resolver"]=="0x8040c8570"
         and p["original_unmodified_target_qword"]=="0x0"
         and p["previously_independently_certified_native_writers"]==61
         and p["source_only_not_native_hardware_proof"] is True
         and p["new_native_writer_attestations"]==0
         and p["original_source_libc_sha256"]==LIBC_SHA
         and p["original_source_ldso_sha256"]==LDSO_SHA,
         "exact source batch preflight never claims writer")
    prior=obj(prev/PRIOR)
    need(prior["original_source_libc_sha256"]==LIBC_SHA
         and prior["original_source_ldso_sha256"]==LDSO_SHA
         and prior["original_source_indices"]==[145,146]
         and prior["prior_independently_certified_native_hardware_target_count"]==59
         and prior["unique_original_libc_native_hardware_writer_target_count"]==61
         and len(prior["two_independent_native_hardware_writer_receipts"])==2
         and sum(map(len,prior["twenty_native_hardware_tamper_cases_rejected"].values()))==20
         and prior["one_single_FEX_guest_process_for_both_writes_proven"] is False,
         "exact prior independent original 61 target hardware receipts")

    original=(source/(SOURCE+".gdb")).read_text()
    need(original.startswith("set pagination off\nset confirm off\n")
         and original.count("watch -location *(unsigned long long *)"+TARGET)==1
         and "awatch -location" not in original,
         "one original exact source-only GDB target")
    return original


def derived_raw_access_gdb(original:str)->str:
    old="watch -location *(unsigned long long *)"+TARGET
    new="awatch -location *(unsigned long long *)"+TARGET
    assert original.count(old)==1
    script=original.replace(old,new).replace(
        "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT",
        "KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS")
    oldp=r'pc=0x%lx x19=0x%lx RAW_NOT_INDEPENDENT=1\n",$pc,$x19'
    newp=r'pc=0x%lx guest_x4=0x%lx x19=0x%lx x28=0x%lx RAW_NOT_INDEPENDENT=1\n",$pc,$x4,$x19,$x28'
    need(script.count(oldp)==1,"original GDB guest register marker")
    script=script.replace(oldp,newp)
    addon=(
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      'printf "KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/3bx $entry\n'
      'x/3bx 0x80100fd60\n'
      'x/3bx 0x8040c860b\n'
    )
    need(script.count('x/i $pc-4\n')==1,"unique disassembly source watch")
    return script.replace('x/i $pc-4\n','x/i $pc-4\n'+addon)


def verify(raw:str)->dict:
    # Exactly TWO hardware lines: an armed GDB declaration and a subsequent
    # observed ARM64 hardware ACCESS trap. Never mistake declaration for hit.
    arm=sole(r"^KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target="+TARGET+
             r" original_zero=1 NOT_NATIVE_PROOF=1$",raw,"zero prewatch arm")
    qwords=list(re.finditer(r"^"+TARGET+r":\s+0x0{16}$",raw,re.M))
    need(len(qwords)==2,"zero QWORD both at arm and after unchanged store")
    events=list(re.finditer(r"^Hardware access \(read/write\) watchpoint 2: -location \*\(unsigned long long \*\)"+TARGET+r"$",raw,re.M))
    need(len(events)==2,"one arm and one real AArch64 hardware ACCESS watch trap")
    val=sole(r"^Value = 0$",raw,"same zero qword at hardware trap")
    hit=sole(r"^KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target="+TARGET+
             r" pc=(0x[0-9a-f]+) guest_x4=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) RAW_NOT_INDEPENDENT=1$",raw,"native ARM64 source register marker")
    rex=hit.group(1,2,3,4)
    pc,store,ptr,jit=(int(x,16) for x in rex)
    need(pc>0xffff00000000 and store==0 and ptr==int(TARGET,16) and jit>0xffff00000000,
         "authentic after-zero AArch64 registers x4=0 and x19 exact original target")
    native=sole(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x4,\s*\[x19\]$",raw,
                "native stored zero via exact AArch64 STLR x4,[x19]")
    need(int(native.group(1),16)==pc-4,"real AArch64 native PC after STLR (not unrelated instruction)")
    hdr=sole(r"^KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",raw,
             "live FEX JIT original x86 GNU ldso STORE")
    need(hdr.group(1)==hex(STORE) and int(hdr.group(2),16)==3 and int(hdr.group(3))==2,
         "genuine original ldso 3-byte STORE native JIT 2 instruction mapping")
    done=sole(r"^KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1$",raw,"real original native raw trace footer")
    need(arm.start()<qwords[0].start()<events[0].start()<events[1].start()
         <val.start()<hit.start()<qwords[1].start()<native.start()<hdr.start()<done.start(),
         "same native process correct GDB hardware arm zero-to-zero write chronology")
    # Original GNU x86 guest instruction bytes must be present in native live
    # GDB x/3bx dumps, not copied from a free-text claim.
    origin=list(re.finditer(r"^0x80100fd60:\s+0x49\s+0x89\s+0x06$",raw,re.M))
    need(len(origin)>=1,"original ldso x86 49 89 06 from actual mapped guest JIT source")
    return {
      "original_source_index":85,
      "source_table":"DT_RELA",
      "original_guest_target":TARGET,
      "original_guest_resolver":"0x8040c8570",
      "original_initial_qword":"0x0",
      "observed_native_stlr_store_value":"0x0",
      "observed_arm64_native_store":"stlr x4, [x19]",
      "source_original_guest_x86_ldso_store":hex(STORE),
      "source_original_guest_x86_ldso_opcode":"498906",
      "native_arm64_pc_after_stlr":hex(pc),
      "source_jit_native_count":2,
      "original_same_guest_CALL_RET_stack_READ_proven":False,
      "native_source_hardware_write_independently_attested":True,
    }


def mutation_rejections(raw:str)->list[str]:
    hitline=sole(r"^KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target=.*$",raw,"real hit").group(0)
    mutations={
      "wrong_target_marker":("target="+TARGET,"target=0x8042014d0"),
      "wrong_live_pre_arm_qword":(TARGET+":\t0x0000000000000000",TARGET+":\t0x0000000000000001"),
      "missing_hardware_access_trap":("\nValue = 0\n","\nValue = 1\n"),
      "wrong_native_x4_store_value":("guest_x4=0x0","guest_x4=0x1"),
      "wrong_native_x19_target":("x19="+TARGET,"x19=0x8042014d0"),
      "invalid_native_x28":(re.search(r"x28=0x[0-9a-f]+",hitline).group(0),"x28=0x0"),
      "wrong_native_store_opcode":("stlr\tx4, [x19]","ldar\tx4, [x19]"),
      "wrong_native_gnu_jit_entry":("guest_entry="+hex(STORE),"guest_entry=0x80100fd64"),
      "wrong_native_jit_source_size":("source_size=0x3","source_size=0x2"),
      "wrong_native_count":("native_count=2","native_count=1"),
      "zero_lost_after_store":(TARGET+":\t0x0000000000000000",TARGET+":\t0x0000000000000002"),
      "remove_trace_footer":("KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=1",
                             "KERNIX_G0_IFUNC85_DT_RELA_NO_NATIVE_ATTESTATION=0"),
    }
    rejected=[]
    for key,(before,after) in mutations.items():
        need(before in raw and after!=before,"negative mutation input actually exists "+key)
        fake=raw.replace(before,after,1)
        need(fake!=raw,"mutated log bytes "+key)
        try:verify(fake)
        except AssertionError:rejected.append(key)
        else:raise AssertionError("independent IFUNC85 forged native log ACCEPTED: "+key)
    need(len(rejected)==12,"all 12 fake original GNU writer logs independently rejected")
    return rejected


def run(triad:Path,source:Path,native:Path,previous:Path,out:Path)->dict:
    source_gdb=original_sha_source(triad,source,previous)
    read_back=native/(SOURCE+".gdb")
    need(read_back.is_file() and not read_back.is_symlink() and
         read_back.read_text()==source_gdb,
         "raw native source watch copies immutable original SHA GDB byte-for-byte")
    derived=derived_raw_access_gdb(source_gdb)
    actual=native/(BASE+".gdb")
    need(actual.is_file() and not actual.is_symlink() and actual.read_text()==derived,
         "real FEX native AWATCH JIT trace exact deterministic GNU source derivation")
    p=native/(BASE+".log")
    need(p.is_file() and not p.is_symlink() and 400<len(p.read_bytes())<500000,
         "genuine bounded original AArch64 FEX GDB log")
    raw=p.read_text()
    metadata=obj(native/(BASE+".json"))
    need(metadata["original_source_index"]==85 and
         metadata["original_table"]=="DT_RELA" and
         metadata["original_source_target"]==TARGET and
         metadata["log_sha256"]==hashlib.sha256(raw.encode()).hexdigest() and
         metadata["original_GNU_native_writer_ledger_unchanged"]==61 and
         metadata["raw_access_includes_reads_not_automatically_a_writer"] is True and
         metadata["native_hardware_write_independently_attested"] is False,
         "raw candidate source/hardware fingerprint and NO premature claim")
    exitpath=native/(BASE+".exit")
    need(exitpath.is_file() and not exitpath.is_symlink() and exitpath.read_text().strip()=="0",
         "source FEX awatch genuine native debugger exit")
    receipt=verify(raw)
    rejected=mutation_rejections(raw)
    result={
      "schema":"kernix.g0.original-gnu-ifunc85-dt-rela-zero-real-fex-native-jit-awatch-independent-writer.v1",
      "original_source_libc_sha256":LIBC_SHA,
      "original_source_ldso_sha256":LDSO_SHA,
      "original_source_indices":[85],
      "prior_independently_certified_native_hardware_target_count":61,
      "new_distinct_original_GNU_native_hardware_writer_targets":1,
      "unique_original_libc_native_hardware_writer_target_count":62,
      "one_original_IFUNC85_independent_same_zero_native_hardware_writer_receipt":receipt,
      "twelve_original_IFUNC85_native_forged_witnesses_rejected":rejected,
      "original_IFUNC85_CALL_C3_RET_native_stack_HW_READ_proven":False,
      "all_147_original_libc_RELA_JMPREL_writers_same_process_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_IFUNC85_ZERO_TO_ZERO_ARM64_FEX_NATIVE_WRITER_INDEPENDENT_PROVEN_62_147_NOT_ANDROID")
    return result


if __name__=="__main__":
    need(len(sys.argv)==6,"usage original-triad source-plan native-FEX-raw prior61-proof result.json")
    run(*map(Path,sys.argv[1:]))
