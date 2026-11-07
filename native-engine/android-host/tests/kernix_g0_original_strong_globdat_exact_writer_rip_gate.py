#!/usr/bin/env python3
"""One-opcode exact guest RIP proof for source-pinned original G0 strong GLOB_DAT.

CI diagnostic ONLY. No FEX/guest modification, RELRO sealing, Android or games.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

FEX_SHA = "02e24ca5c01ed0c864466ed573db347336f70170"
ROOT = Path("/tmp/kernix-g2ec2-fex-upstream")
DIST = Path("dist")
LOG = DIST / "original-strong-main-globdat-watch.log"
PREV = DIST / "original-strong-globdat-jit-source-evidence.json"
LD_SO = DIST / "original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
BLOBS = {
    "FEXCore/Source/Interface/Core/ArchHelpers/Arm64Emitter.cpp":
        "3ebadb5aa88de9e5d1454eb88c3b041ff08bbb52",
    "FEXCore/Source/Interface/Core/JIT/JITClass.h":
        "d0b4c5ca6c6568119991358641b3dbd9c1165d0a",
    "FEXCore/include/FEXCore/Core/X86Enums.h":
        "8c3b1c9f36ec0db5e58f6fe719b389e7bf16c93d",
    "FEXCore/Source/Utils/variable_length_integer.h":
        "6d29a6ab92b09fefc0541702e48e68153d9a9c5c",
}

def check(ok, reason):
    if not ok:
        raise AssertionError(reason)

def register_source():
    sha = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    check(sha == FEX_SHA, "FEX commit changed")
    for rel, expected in BLOBS.items():
        actual = subprocess.check_output(
            ["git", "-C", str(ROOT), "hash-object", rel], text=True).strip()
        check(actual == expected, "FEX source changed: " + rel)
    emitter = (ROOT / list(BLOBS)[0]).read_text()
    resolver = (ROOT / "FEXCore/Source/Interface/Core/JIT/JITClass.h").read_text()
    enum = (ROOT / "FEXCore/include/FEXCore/Core/X86Enums.h").read_text()
    check(emitter.count("namespace x64 {") == 1, "x64 namespace changed")
    block = emitter.split("namespace x64 {", 1)[1].split("#else", 1)[0]
    def get(name, size):
        expr = (r"constexpr std::array<ARMEmitter::Register,\s*"
                + str(size) + r">\s*" + name + r"\s*=\s*\{([^}]*)\}")
        m = re.findall(expr, block, re.S)
        check(len(m) == 1, "nonunique " + name)
        regs = [int(x) for x in re.findall(r"ARMEmitter::Reg::r(\d+)", m[0])]
        if name == "SRA":
            check(len(regs) == 16 and
                  re.search(r"REG_PF\s*,\s*REG_AF\s*,", m[0]),
                  "SRA pseudo PF/AF layout changed")
            return regs + [-1,-2]
        check(len(regs) == size, "RA changed")
        return regs
    static, dynamic = get("SRA",18), get("RA",7)
    check(static[:16] == [4,7,5,6,8,9,10,11,12,13,14,15,16,17,19,29],
          "source fixed registers changed")
    check(dynamic == [20,21,22,23,24,30,18], "dynamic register map changed")
    check(static[0] == 4 and static[9] == 13 and 4 not in dynamic and
          13 not in dynamic, "RAX/R9 no longer map to x4/x13")
    check("REG_RAX = 0," in enum and "REG_R9 = 9," in enum and
          "StaticRegisters = x64::SRA;" in emitter and
          "GeneralRegisters = x64::RA;" in emitter and
          "if (EmitterCTX->Config.Is64BitMode()) {" in emitter and
          "if (RegClass == IR::RegClass::GPRFixed) {" in resolver and
          "return StaticRegisters[Reg.Reg];" in resolver,
          "original x86-64 fixed register resolution changed")
    cpp = Path("native-engine/android-host/tests/"
        "kernix_g0_original_fex_full_ptload_source_executable_range_arm64.cpp")
    check(re.search(r"(?m)^\s*host\.ProcessFeatures\.Is64BitMode\s*=\s*1\s*;",
                    cpp.read_text()) is not None,
          "not original 64-bit x86 guest")
    return static

def memory_dump(log, begin, end, start, count):
    check(log.count(begin)==1 and log.count(end)==1, "missing/duplicate marker")
    section=log.split(begin,1)[1].split(end,1)[0]
    rows=re.findall(r"(?m)^[ \t]*(0x[0-9a-fA-F]+):[ \t]*"
                    r"((?:0x[0-9a-fA-F]{2}[ \t]*)+)$",section)
    values=[]
    for i,(a,payload) in enumerate(rows):
        check(int(a,16)==start+i*8, "nonconsecutive GDB guest memory")
        row=[int(v,16) for v in re.findall(r"0x[0-9a-fA-F]{2}",payload)]
        check(len(row)==8, "truncated GDB row")
        values+=row
    check(len(values)==count, "unexpected GDB memory byte count")
    return bytes(values)

def gate(w):
    return (w["rip"]==0x80100FB8B and w["size"]==3 and
            w["file"]==0xFB8B and w["opcode"]=="4c8908" and
            w["version"]=="GLIBC_2.34" and
            w["pairs"]==[(4,0),(8,0)] and w["hostoff"]==16 and
            w["instruction"]==("stlr","x13, [x4]") and
            w["map"]==(4,13) and
            w["values"]==(0x800003FD8,0x80402A200))

def main():
    static=register_source()
    prior=json.loads(PREV.read_text())
    check(prior.get("source_pinned_original_ldso_JIT_guest_block_proven") is True
          and prior.get("observed_hardware_write") is True
          and prior.get("strong_GLOB_DAT_symbol_version_and_pointer_source_verified") is True,
          "previous source/live-symbol proof not passed")
    required={
        "JIT_guest_block_entry":"0x80100fb8b",
        "JIT_guest_block_size":3,
        "original_ldso_source_file_offset":"0xfb8b",
        "original_ldso_guest_source_bytes":"4c8908",
        "target":"0x800003fd8",
        "postwrite_guest_pointer":"0x80402a200",
        "imported_symbol_required_version":"GLIBC_2.34",
        "original_libc_export_symbol":"__libc_start_main@@GLIBC_2.34",
    }
    for k,v in required.items():
        check(prior.get(k)==v, "source evidence changed: "+k)
    ldso=LD_SO.read_bytes()
    check(len(ldso)==235408 and
          hashlib.sha256(ldso).hexdigest()==
          "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae" and
          ldso[0xFB8B:0xFB8E]==bytes.fromhex("4c8908"),
          "source original ld-linux SHA/opcode mismatch")
    dis=subprocess.run(["x86_64-linux-gnu-objdump","-d","-M","intel",
         "--start-address=0xfb8b","--stop-address=0xfb8e",str(LD_SO)],
         capture_output=True,text=True,check=True,timeout=12).stdout
    (DIST/"original-strong-globdat-writer-objdump.txt").write_text(dis)
    check(re.search(r"(?im)^\s*fb8b:\s+4c\s+89\s+08\s+mov\s+"
                    r"QWORD PTR \[rax\],r9\s*$",dis),
          "source x86 writer opcode semantics not MOV [RAX], R9")
    log=LOG.read_text(errors="replace")
    m=re.search(
        r"(?m)^KERNIX_G0_STRONG_GLOB_JIT_SOURCE_HEADER_READONLY "
        r"header=(0x[0-9a-fA-F]+) offset=(0x[0-9a-fA-F]+) "
        r"size=(0x[0-9a-fA-F]+) guest_entry=(0x[0-9a-fA-F]+) "
        r"guest_size=(0x[0-9a-fA-F]+) rip_entries=(\d+) "
        r"rip_entry_offset=(0x[0-9a-fA-F]+) host_writer=(0x[0-9a-fA-F]+)$",
        log)
    check(m is not None,"original FEX JIT header missing")
    head,tail,size,rip,guestlen,n,entryoff,writer=(int(x,0) for x in m.groups())
    check(head>0 and tail==0x48 and size==0x80 and rip==0x80100FB8B
          and guestlen==3 and n==2 and entryoff==0x28 and writer==head+16,
          "active original FEX JIT host/guest block mismatch")
    table=memory_dump(log,"KERNIX_G0_STRONG_GLOB_JIT_RIP_MAP_BYTES_START",
            "KERNIX_G0_STRONG_GLOB_JIT_RIP_MAP_BYTES_END",
            head+tail+entryoff,16)
    check(table==bytes.fromhex("80018002")+bytes(12),"original RIP map mismatch")
    def dec(pos):
        check(table[pos]&0xC0==0x80,"FEX source vl64pair type mismatch")
        guest=table[pos]&63
        guest=guest-64 if guest>=32 else guest
        arm=table[pos+1]
        arm=arm-256 if arm>=128 else arm
        return arm*4,guest
    pairs=[dec(0),dec(2)]
    check(pairs==[(4,0),(8,0)],"FEX host PC may map to another x86 RIP")
    actual=memory_dump(log,"KERNIX_G0_STRONG_GLOB_JIT_GUEST_SOURCE_BYTES_START",
            "KERNIX_G0_STRONG_GLOB_JIT_GUEST_SOURCE_BYTES_END",rip,24)
    check(actual[:3]==ldso[0xFB8B:0xFB8E],"live x86 bytes != original ELF")
    regs={}
    for reg in ("pc","x4","x13"):
        vals=re.findall(r"(?m)^"+reg+r"\s+(0x[0-9a-fA-F]+)",log)
        check(len(vals)==1,"native live register missing/duplicated: "+reg)
        regs[reg]=int(vals[0],16)
    check(regs==dict(pc=writer+4,x4=0x800003FD8,x13=0x80402A200),
          "real STLR hardware watch registers mismatch")
    instructions={}
    for x in re.finditer(
        r"(?m)^[ \t]*(0x[0-9a-fA-F]+):[ \t]+([a-z][a-z0-9.]*)"
        r"(?:[ \t]+([^\n]+))?$",log):
        pos=int(x.group(1),16)
        check(pos not in instructions,"duplicate native JIT address")
        instructions[pos]=(x.group(2),(x.group(3) or "").strip())
    want={
        head+4:("adr","x0, "+hex(head)),
        head+8:("str","x0, [x28]"),
        head+12:("nop",""),
        head+16:("stlr","x13, [x4]"),
    }
    check(all(instructions.get(k)==v for k,v in want.items()),
          "x4/x13 modified before native STLR in JIT")
    w=dict(rip=rip,size=guestlen,file=0xFB8B,opcode=actual[:3].hex(),
           version=prior["imported_symbol_required_version"],pairs=pairs,
           hostoff=writer-head,instruction=instructions[writer],
           map=(static[0],static[9]),values=(regs["x4"],regs["x13"]))
    check(gate(w),"independent exact source guest RIP proof incomplete")
    bad=dict(rip=rip+1,size=2,file=0xFB8C,opcode="4c8909",
             version="GLIBC_2.2.5",pairs=[(4,0),(8,1)],
             hostoff=12,instruction=("stlr","x13, [x5]"),
             map=(4,14),values=(0x800003FD8,0x80402A201))
    for k,corrupt in bad.items():
        modified=dict(w);modified[k]=corrupt
        check(not gate(modified),"corrupt x86 RIP witness accepted: "+k)
    result=dict(prior)
    result.update(schema="kernix.g0.strong-globdat-exact-guest-rip.v1",
        original_FEX_source_commit=FEX_SHA,
        source_x86_instruction="mov QWORD PTR [rax],r9",
        source_RAX_arm64_x=static[0],source_R9_arm64_x=static[9],
        live_x4=hex(regs["x4"]),live_x13=hex(regs["x13"]),
        FEX_source_rip_pairs=pairs,
        original_guest_writer_RIP=hex(rip),
        original_guest_writer_RIP_proven=True,
        exact_original_guest_writer_RIP_proven=True,
        original_main_all_relocations_proven=False,
        original_main_RELRO_sealed=False,
        Android_Bionic_or_phone_executed=False,
        Wine_Proton_or_gameplay_proven=False)
    (DIST/"original-strong-globdat-exact-writer-rip-evidence.json").write_text(
        json.dumps(result,indent=2)+"\n")
    print("KERNIX_G0_STRONG_GLOB_DAT_EXACT_ORIGINAL_LDSO_GUEST_WRITER_RIP_PROVEN"
          +" rip="+hex(rip)+" live_rax="+hex(regs["x4"])+" live_r9="+hex(regs["x13"]))
    print("KERNIX_G0_STRONG_GLOB_DAT_X86_RIP_TEN_MUTATION_NEGATIVES_PASS")
    print("KERNIX_G0_OTHER_RELOCATIONS_AND_MAIN_RELRO_GATES_REMAIN_CLOSED")

if __name__=="__main__":
    main()
