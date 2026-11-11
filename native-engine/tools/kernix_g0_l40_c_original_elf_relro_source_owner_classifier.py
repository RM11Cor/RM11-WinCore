#!/usr/bin/env python3
"""Classify real GNU ldso-vs-main RELRO source from SHA original ELF PHT.

This is an ORIGINAL ELF / actual FEX GDB rejection DIAGNOSTIC.
It does NOT authorize a native mprotect, change memory permissions,
bypass a fail-closed owner check, attest actual IFUNC/JUMP_SLOT writes,
or prove a full GNU/Android/Wine loader. The exact guest request has
to pass a future independent LIVE owner/VMA/protection audit.
"""
from __future__ import annotations
import hashlib,json,re,struct,sys
from pathlib import Path
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA

SCHEMA="kernix.g0.l40c.true-original-elf-phdr-PT_GNU_RELRO-source-owner-classifier-before-reject.v1"
OUT="KERNIX-G0-L40-C-Original-GNU-Main-vs-Ldso-RELRO-FEX-Source-Owner-Only-NO-Mprotect-Approval.json"
MAIN_SHA="9fb072db2732c7c6a1b2a53bd946d54904feaac5980e0d79b39f7ce300784412"
REJECTION="KERNIX_G0_REAL_NEXT_MAIN_RELRO_SOURCE_AUDIT_REJECT"
PAT=re.compile(r"^"+REJECTION+r" request=([0-9a-f]+) expected=([0-9a-f]+)"
               r" relro_first=([0-9a-f]+) relro_end=([0-9a-f]+)"
               r" source=(\d+) owner=(\d+) live=([rwxps-]{4})$",re.M)
MAIN_BASE=0x800000000
LDSO_BASE=0x801000000
PAGE=4096
RELRO=0x6474e552

def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_C_RELRO_OWNER_SOURCE_FAIL_CLOSED: "+msg)
def read(p:Path,limit=3000000):
    need(p.is_file() and not p.is_symlink(),"real bounded immutable GNU original source "+str(p))
    data=p.read_bytes()
    need(0<len(data)<=limit,"bounded GNU original ELF bytes or raw FEX trace "+str(p))
    return data
def original_phdr_relro(blob:bytes,name:str):
    need(len(blob)>=64 and blob[:4]==b"\x7fELF" and blob[4]==2 and blob[5]==1
         and blob[6]==1,"actual ELF64 little endian original GNU "+name)
    (etype,machine)=struct.unpack_from("<HH",blob,16)
    need(machine==62 and etype in (2,3),"real x86_64 ET_EXEC or ET_DYN source "+name)
    phoff=struct.unpack_from("<Q",blob,32)[0]
    phentsize,phnum=struct.unpack_from("<HH",blob,54)
    need(phentsize==56 and 1<=phnum<=128 and phoff+phnum*56<=len(blob),
         "source original GNU ELF program headers not invented")
    relros=[]
    for i in range(phnum):
        ph=struct.unpack_from("<IIQQQQQQ",blob,phoff+56*i)
        if ph[0]==RELRO:
            relros.append({"source_relro_vaddr":ph[3],"source_relro_file_offset":ph[2],
                           "source_relro_filesz":ph[5],"source_relro_memsz":ph[6]})
    need(len(relros)==1,"exact one authentic original GNU PT_GNU_RELRO "+name)
    r=relros[0]
    need(r["source_relro_memsz"]>0 and r["source_relro_memsz"]<=0x10000,
         "finite source RELRO section in original GNU ELF")
    return r
def range_at(r:dict,base:int):
    start=(base+r["source_relro_vaddr"])//PAGE*PAGE
    end=(base+r["source_relro_vaddr"]+r["source_relro_memsz"]+PAGE-1)//PAGE*PAGE
    need(start<end and end-start<=65536,"bounded exact original GNU RELRO page rounding")
    return start,end
def classify(trace:str,main:dict,ldso:dict):
    hits=list(PAT.finditer(trace))
    need(len(hits)==1,"exact one genuine original native FEX main-policy rejection marker")
    request,expected,first,end=map(lambda s:int(s,16),hits[0].groups()[:4])
    source,owner=map(int,hits[0].groups()[4:6])
    live=hits[0][7]
    actual_main=range_at(main,MAIN_BASE)
    actual_ldso=range_at(ldso,LDSO_BASE)
    need(actual_main==(0x800003000,0x800004000),
         "SHA original GNU main PT_GNU_RELRO exact 4K page")
    need(actual_ldso==(0x801036000,0x801038000),
         "SHA original GNU ld-linux PT_GNU_RELRO exact two 4K pages")
    need(request==actual_ldso[0] and request!=actual_main[0]
         and expected==actual_main[0]
         and actual_main[1]<=actual_ldso[0]
         and first==end==source==owner==0 and live=="r--p",
         "failed actual host source main RELRO owner gate rejected LD-SO page, not safe to approve")
    return {"rejected_guest_mprotect_request":hex(request),
            "real_original_ELF_source_ownership":"ld-linux-x86-64.so.2 PT_GNU_RELRO",
            "original_main_PT_GNU_RELRO_pages":[hex(x) for x in actual_main],
            "original_ldso_PT_GNU_RELRO_pages":[hex(x) for x in actual_ldso],
            "bad_main_gate_expected_page":hex(expected),
            "original_host_main_owner_audit_safely_rejected_unproven_address":True,
            "original_guest_policy_rejection_was_a_full_loader_success":False,
            "true_native_guest_mprotect_authorized_by_this_classifier":False}
def forged_tests(trace,main,ldso):
    hits=list(PAT.finditer(trace))
    need(len(hits)==1,"actual unique original source marker")
    h=hits[0]
    groups=list(h.groups())
    mutations=[
      ("request_wrong",0,"800003000"),
      ("request_outside",0,"801042000"),
      ("expected_wrong",1,"801036000"),
      ("expected_unmapped",1,"800011000"),
      ("falsified_relro_first",2,"801036000"),
      ("falsified_relro_end",3,"801038000"),
      ("falsified_source_owner",4,"1"),
      ("falsified_host_owner",5,"1"),
      ("falsified_linux_rights",6,"rw-p"),
      ("wrong_request_null",0,"0"),
      ("wrong_expected_null",1,"0"),
      ("wrong_request_nearby",0,"801037000"),
    ]
    need(len(mutations)==12,"12 original source true FEX address ownership counterfeit tests")
    denied=[]
    for name,n,val in mutations:
        fields=groups.copy()
        need(fields[n]!=val,"real falsification changes actual GDB evidence")
        fields[n]=val
        replacement=(REJECTION+" request="+fields[0]+" expected="+fields[1]
                     +" relro_first="+fields[2]+" relro_end="+fields[3]
                     +" source="+fields[4]+" owner="+fields[5]+" live="+fields[6])
        bogus=trace[:h.start()]+replacement+trace[h.end():]
        try:classify(bogus,main,ldso)
        except AssertionError:denied.append(name)
        else:raise AssertionError("FORGED_G0_C_MAIN_LDSO_RELRO_OWNER_EVIDENCE_ACCEPTED "+name)
    need(len(denied)==12,"no forged native original PT_GNU_RELRO ownership accepted")
    return denied

def run(triad:Path,trace:Path,out:Path):
    mainbytes=read(triad/"bin/kernix-g2e-dynamic-guest",25000)
    ldsobytes=read(triad/"lib64/ld-linux-x86-64.so.2",600000)
    libcbytes=read(triad/"lib/x86_64-linux-gnu/libc.so.6")
    need(hashlib.sha256(mainbytes).hexdigest()==MAIN_SHA
         and hashlib.sha256(ldsobytes).hexdigest()==LDSO_SHA
         and hashlib.sha256(libcbytes).hexdigest()==LIBC_SHA,
         "three SHA-pinned original GNU source ELF images identical to actual FEX guest")
    srcmain=original_phdr_relro(mainbytes,"main")
    srcldso=original_phdr_relro(ldsobytes,"ld-linux")
    actual=read(trace,250000).decode(errors="replace")
    data=classify(actual,srcmain,srcldso)
    denied=forged_tests(actual,srcmain,srcldso)
    out.mkdir(parents=True,exist_ok=True)
    result={
      "schema":SCHEMA,"original_main_ELF_sha256":MAIN_SHA,
      "original_ldso_ELF_sha256":LDSO_SHA,"original_libc_ELF_sha256":LIBC_SHA,
      "source_original_main_pt_gnu_relro":srcmain,
      "source_original_ldso_pt_gnu_relro":srcldso,
      "true_native_ARM64_FEX_GDB_rejection_log_sha256":hashlib.sha256(actual.encode()).hexdigest(),
      **data,
      "twelve_false_owner_mprotect_source_evidences_rejected":denied,
      "stage_C_40_original_native_writers_one_FEX_pid_proven":False,
      "original_147_full_GNU_loader_closure_proven":False,
      "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (out/OUT).write_text(json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_C_ORIGINAL_GNU_MAIN_VS_LDSO_PT_GNU_RELRO_SOURCE_OWNER_SHA_PROVEN",
          "real_request="+data["rejected_guest_mprotect_request"],
          "belongs=ldso", "12_SPOOFED_REJECTIONS_DENIED",
          "NO_NATIVE_MPROTECT_APPROVAL_NO_FULL_LOADER",flush=True)
    return result
if __name__=="__main__":
    need(len(sys.argv)==4,"usage original_SHA_source_triad original_FEX_reject_GDB_log out")
    run(*map(Path,sys.argv[1:]))
