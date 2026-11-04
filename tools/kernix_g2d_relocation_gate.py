#!/usr/bin/env python3
"""KERNIX G2-D genuine x86 PLT/DSO import, bounded 16KiB-page-safe audit.

This only inspects exact self-authored MIT-only ELF bytes, applies a genuine
R_X86_64_JUMP_SLOT relocation to a DISPOSABLE bytearray, and rejects tampering.
It does not run x86 instructions or implement a Linux dynamic interpreter.
Actual FEX guest execution is a *distinct later evidence gate*.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EH=struct.Struct("<16sHHIQQQIHHHHHH")
PH=struct.Struct("<IIQQQQQQ")
DYN=struct.Struct("<qQ")
RELA=struct.Struct("<QQq")
SYM=struct.Struct("<IBBHQQ")
PT_LOAD=1
PT_DYNAMIC=2
PF_X=1
PF_W=2
PAGE=16384
DT_NULL=0
DT_NEEDED=1
DT_PLTRELSZ=2
DT_STRTAB=5
DT_SYMTAB=6
DT_RELA=7
DT_STRSZ=10
DT_SYMENT=11
DT_SONAME=14
DT_PLTREL=20
DT_JMPREL=23
R_X86_64_JUMP_SLOT=7
SYMBOL=b"kernix_g2d_imported_value"
LIB=b"libkernix-g2d-mit-import.so.1"
INTERP=b"/lib64/ld-kernix-g2d-mit-import-test.so.1"
EXPECTED_RAX=0x4B45524E49584731
MAIN="bin/kernix-g2d-import-app"
DSO="lib/x86_64-linux-gnu/libkernix-g2d-mit-import.so.1"
LOADER="lib64/ld-kernix-g2d-mit-import-test.so.1"
FILE_ORDER=(MAIN,DSO,LOADER)
MAX_FILE=256*1024
MAIN_BIAS=0x400000000
DSO_BIAS=0x500000000


def require(ok,reason):
    if not ok:
        raise ValueError("G2D_MIT_BOUND_PLT_RELOCATION_REJECTED:"+reason)


class Elf:
    def __init__(self,data,which):
        self.name=which
        self.raw=bytes(data)
        require(0<len(self.raw)<=MAX_FILE and len(self.raw)>=EH.size,
                which+":invalid file length")
        fields=EH.unpack_from(self.raw)
        ident,e_type,machine,version,entry,phoff,_,_,ehsize,phentsz,phnum,*_=fields
        require(ident[:7]==b"\x7fELF\x02\x01\x01" and e_type==3 and
                machine==62 and version==1 and ehsize==EH.size and
                phentsz==PH.size and 1<=phnum<=24,
                which+":not ET_DYN x86-64 ELF")
        require(phoff<=len(self.raw) and phnum*phentsz<=len(self.raw)-phoff,
                which+":program headers outside data")
        self.entry=entry
        self.ph=[PH.unpack_from(self.raw,phoff+i*phentsz)
                 for i in range(phnum)]
        self.load=[p for p in self.ph if p[0]==PT_LOAD and p[6]>0]
        require(2<=len(self.load)<=8,which+":wrong number of load segments")
        used={}
        has_rx=False
        has_rw=False
        for p in self.load:
            typ,flags,off,vaddr,_,filesz,memsz,align=p
            require(flags & ~7==0 and flags & PF_X and not flags & PF_W
                    or flags & ~7==0 and not(flags & PF_X and flags & PF_W),
                    which+":RWX or unknown permission")
            require(align>=PAGE and align&(align-1)==0 and
                    ((vaddr-off)%PAGE)==0 and
                    0<=filesz<=memsz and off<=len(self.raw) and
                    filesz<=len(self.raw)-off and
                    vaddr<1<<47 and memsz<(1<<47)-vaddr,
                    which+":unsafe 16KiB PT_LOAD")
            has_rx |= bool(flags & PF_X)
            has_rw |= bool(flags & PF_W)
            for i in range(vaddr//PAGE,(vaddr+memsz+PAGE-1)//PAGE):
                require(i not in used,which+":two segments share host page")
                used[i]=p
        require(has_rx and has_rw,which+":expected separate RX and RW segments")
        self.dynamic=[]
        dynph=[p for p in self.ph if p[0]==PT_DYNAMIC]
        require(len(dynph)==1,which+":one PT_DYNAMIC required")
        _,_,off,_,_,size,memsz,_=dynph[0]
        require(size<=memsz and size%DYN.size==0 and size<=128*DYN.size and
                off<=len(self.raw) and size<=len(self.raw)-off,
                which+":unbounded dynamic")
        has_null=False
        for n in range(0,size,DYN.size):
            tag,val=DYN.unpack_from(self.raw,off+n)
            if tag==DT_NULL:
                has_null=True
                break
            self.dynamic.append((tag,val))
        require(has_null,which+":DT_NULL missing")

    def unique(self,tag,required=True):
        values=[val for t,val in self.dynamic if t==tag]
        require(len(values)==(1 if required else 0),self.name+":dynamic tag mismatch "+str(tag))
        return values[0] if required else None

    def file_vaddr(self,vaddr,count,writable=None,executable=None):
        require(count>=0 and vaddr>=0 and vaddr+count<=1<<47,
                self.name+":address overflow")
        found=[]
        for p in self.load:
            _,flags,off,first,_,file_bytes,mem_bytes,_=p
            if vaddr<first or vaddr+count>first+file_bytes:
                continue
            if writable is not None and bool(flags&PF_W)!=writable:
                continue
            if executable is not None and bool(flags&PF_X)!=executable:
                continue
            found.append((off+vaddr-first,flags))
        require(len(found)==1,self.name+":invalid or ambiguous ELF virtual address")
        offset,_=found[0]
        return offset

    def strtab(self,index):
        start=self.unique(DT_STRTAB)
        size=self.unique(DT_STRSZ)
        require(size>=1 and size<=4096 and index<size,
                self.name+":string table range")
        off=self.file_vaddr(start+index,size-index,writable=False)
        entry=self.raw[off:off+size-index]
        nul=entry.find(b"\0")
        require(0<=nul<=127,self.name+":missing or oversized symbol")
        return entry[:nul]

    def sym(self,idx):
        size=self.unique(DT_SYMENT)
        require(size==SYM.size and 0<=idx<=32,
                self.name+":symbol entry size/index mismatch")
        addr=self.unique(DT_SYMTAB)+idx*SYM.size
        return SYM.unpack_from(self.raw,self.file_vaddr(addr,SYM.size,writable=False))

    def file_sha(self):
        return hashlib.sha256(self.raw).hexdigest()


def audit_blobs(main_raw,provider_raw,loader_raw):
    m=Elf(main_raw,"main")
    p=Elf(provider_raw,"provider")
    ld=Elf(loader_raw,"interpreter-not-executed")
    require(m.strtab(m.unique(DT_NEEDED))==LIB,"main imports unexpected library")
    require(p.strtab(p.unique(DT_SONAME))==LIB,"provider SONAME mismatch")
    require(not any(x==DT_NEEDED for x,_ in p.dynamic),
            "provider uses transitive shared libraries")
    require(not any(x==DT_NEEDED for x,_ in ld.dynamic),
            "stub interpreter uses external libraries")
    require(m.unique(DT_PLTREL)==DT_RELA and
            m.unique(DT_PLTRELSZ)==RELA.size,
            "only one ELF64 RELA PLT relocation allowed")
    require(not any(tag in (DT_RELA,) for tag,_ in m.dynamic),
            "unexpected non-PLT relocations")
    rela_addr=m.unique(DT_JMPREL)
    rela=RELA.unpack_from(m.raw,m.file_vaddr(rela_addr,RELA.size,writable=False))
    r_offset,r_info,addend=rela
    symidx=r_info>>32
    rtype=r_info & 0xffffffff
    require(rtype==R_X86_64_JUMP_SLOT and symidx==1 and addend==0,
            "wrong relocation type, symbol index or addend")
    sym=m.sym(symidx)
    name,info,other,shndx,val,sym_size=sym
    require(m.strtab(name)==SYMBOL and shndx==0 and
            info>>4==1 and (info&15) in (0,2),
            "main undefined imported PLT symbol wrong")
    # This is explicitly ONE trusted MIT-owned provider, never arbitrary
    # Linux symbol lookup or user-chosen relocation.
    exported=p.sym(1)
    exp_name,exp_info,exp_other,exp_shndx,exp_value,exp_size=exported
    require(p.strtab(exp_name)==SYMBOL and exp_shndx!=0 and
            exp_info>>4==1 and (exp_info&15)==2 and
            exp_other==0 and exp_size==11,
            "one exact exported x86 DSO FUNC required")
    codeoff=p.file_vaddr(exp_value,exp_size,executable=True)
    code=p.raw[codeoff:codeoff+exp_size]
    require(code==b"\x48\xb8"+struct.pack("<Q",0x4b45524e49584720)+b"\xc3",
            "external DSO code not pinned test function")
    slotoff=m.file_vaddr(r_offset,8,writable=True)
    # Simulate one real ELF RELA patch in a fresh, not executable memory
    # bytearray. No mprotect, guest trampoline, process execute or FEX.
    scratch=bytearray(m.raw)
    target=DSO_BIAS+exp_value
    struct.pack_into("<Q",scratch,slotoff,target)
    require(struct.unpack_from("<Q",scratch,slotoff)[0]==target,
            "relocated writable PLT GOT did not match DSO")
    require(m.raw[:slotoff]==scratch[:slotoff] and
            m.raw[slotoff+8:]==scratch[slotoff+8:],
            "relocation wrote outside exactly eight GOT bytes")
    require(0<exp_value<1<<47 and r_offset<1<<47,
            "fixed guest export and GOT outside 47-bit VA space")
    return {
      "schema":"kernix.g2d.real-x86-PLT-import-one-JUMP_SLOT-boundary.v1",
      "main_ELF_SHA256":m.file_sha(),
      "provider_x86_DSO_SHA256":p.file_sha(),
      "interpreter_stub_ELF_SHA256":ld.file_sha(),
      "host_page_alignment_required":16384,
      "relocation":"R_X86_64_JUMP_SLOT",
      "relocation_count":1,
      "symbol":SYMBOL.decode(),
      "symbol_resolved_from_separate_x86_DSO":True,
      "relocated_guest_GOT_vaddr":hex(r_offset),
      "external_x86_function_vaddr":hex(exp_value),
      "expected_final_guest_RAX":hex(EXPECTED_RAX),
      "relocation_applied_only_to_disposable_host_bytearray":True,
      "guest_executable_PT_LOAD_modified":False,
      "real_dynamic_interpreter_implemented":False,
      "interpreter_executed":False,
      "x86_guest_executed_in_this_gate":False,
      "original_FEX_executed_in_this_gate":False,
      "android_device_executed_in_this_gate":False,
      "wine_or_windows_game_executed":False
    }


def filebytes(root):
    root=Path(root)
    for name in FILE_ORDER:
        p=root/name
        require(p.is_file() and not p.is_symlink() and p.stat().st_size<=MAX_FILE,
                "guest file not original regular immutable input:"+name)
    return tuple((root/name).read_bytes() for name in FILE_ORDER)


def reject(call,reason):
    try:call()
    except (ValueError,struct.error):
        return
    raise AssertionError("Unsafe G2-D relocation accepted: "+reason)


def adversarial(blobs):
    main,provider,loader=map(bytearray,blobs)
    # Authentic linker output has one fixed PLT RELOCATION at 0x2f8.
    original=bytes(main)
    elf=Elf(original,"main")
    rela=elf.unique(DT_JMPREL)
    off=elf.file_vaddr(rela,RELA.size,writable=False)
    for label,difference in (("wrong relocation type",1),
                             ("wrong imported symbol index",0x100000000),
                             ("wrong relocation addend",0x10000000000000000)):
        bad=bytearray(original)
        if label=="wrong relocation type":
            bad[off+8]^=0x10
        elif label=="wrong imported symbol index":
            bad[off+12]^=0x1
        else:
            bad[off+16]^=0x01
        reject(lambda: audit_blobs(bad,provider,loader),label)
    bad=bytearray(provider)
    bad[Elf(bad,"provider").file_vaddr(
        Elf(bad,"provider").sym(1)[4],11,executable=True)+4]^=1
    reject(lambda:audit_blobs(main,bad,loader),"modified imported machine code")
    bad=bytearray(original)
    # Replacing the only DT_NEEDED string must fail closed.
    at=original.find(LIB)
    require(at>=0,"MIT DSO link name absent")
    bad[at]^=0x01
    reject(lambda:audit_blobs(bad,provider,loader),"wrong library name")
    bad=bytearray(original)
    require(b"\x7fELF" in bad[:4],"ELF header missing")
    bad[4]=1
    reject(lambda:audit_blobs(bad,provider,loader),"ELF32 substituted")
    print("KERNIX_G2D_ONE_PLT_RELA_INTEGRITY_SYMBOL_DSO_NEGATIVE_TESTS_PASS_NO_GUEST_EXEC")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("root")
    parser.add_argument("report")
    args=parser.parse_args()
    blobs=filebytes(args.root)
    result=audit_blobs(*blobs)
    adversarial(blobs)
    dest=Path(args.report)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("KERNIX_G2D_GENUINE_MIT_X86_64_PLT_JUMP_SLOT_EXTERNAL_DSO_RELOCATION_AUDITED_PASS_NOT_FEX")


if __name__=="__main__":
    main()
