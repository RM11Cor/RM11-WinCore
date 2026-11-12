#!/usr/bin/env python3
"""Experimental static x86-64 function lifter to native C++/ARM64.

Build-time Capstone disassembly -> C++ control-flow and register semantics ->
normal Clang/GCC compilation to ARM64. Runtime needs NO x86 binary decoder,
NO Wine/FEX, and never accesses the original PC binary at runtime.

Initial support intentionally bounded to simple basic-block functions
with Windows x64 register arguments RCX/RDX/R8/R9. Incorrectly understood
instructions FAIL CLOSED; tests are synthetic, not actual CarX game logic.
"""
from __future__ import annotations
import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

REGS={
    "rax":0, "rcx":1, "rdx":2, "rbx":3, "rsp":4,
    "rbp":5, "rsi":6, "rdi":7, "r8":8, "r9":9,
    "r10":10, "r11":11, "r12":12, "r13":13,
    "r14":14, "r15":15,
    # x86-64 32-bit writes zero-extend to the full 64-bit GPR.
    "eax":0, "ecx":1, "edx":2, "ebx":3, "esp":4,
    "ebp":5, "esi":6, "edi":7, "r8d":8, "r9d":9,
    "r10d":10, "r11d":11, "r12d":12, "r13d":13,
    "r14d":14, "r15d":15,
    "ax":0, "cx":1, "dx":2, "bx":3, "sp":4,
    "bp":5, "si":6, "di":7, "r8w":8, "r9w":9,
    "r10w":10, "r11w":11, "r12w":12, "r13w":13,
    "r14w":14, "r15w":15,
    "al":0, "cl":1, "dl":2, "bl":3, "spl":4,
    "bpl":5, "sil":6, "dil":7, "r8b":8, "r9b":9,
    "r10b":10, "r11b":11, "r12b":12, "r13b":13,
    "r14b":14, "r15b":15,
    "ah":0, "ch":1, "dh":2, "bh":3,
}
JCC={
    "je":"zf","jz":"zf","jne":"!zf","jnz":"!zf",
    "ja":"(!cf && !zf)","jnbe":"(!cf && !zf)",
    "jae":"!cf","jnb":"!cf","jnc":"!cf",
    "jb":"cf","jnae":"cf","jc":"cf",
    "jbe":"(cf || zf)","jna":"(cf || zf)",
    "jl":"(sf != of)","jnge":"(sf != of)",
    "jle":"(zf || sf != of)","jng":"(zf || sf != of)",
    "jg":"(!zf && sf == of)","jnle":"(!zf && sf == of)",
    "jge":"(sf == of)","jnl":"(sf == of)",
}
MAX_BYTES=65536
MAX_INSNS=4096

class UnsupportedGuestCode(ValueError):
    pass

@dataclass
class Lifted:
    entry:int
    insn_count:int
    code:str

def _unsupported(ins,why):
    raise UnsupportedGuestCode(
        "Unsupported x64 guest instruction at 0x%x: %s %s (%s)"
        %(ins.address,ins.mnemonic,ins.op_str,why))

def lift_function(code:bytes,base:int=0x1000)->Lifted:
    if not code or len(code)>MAX_BYTES:
        raise UnsupportedGuestCode("x86 function sample size must be 1..65536")
    if base<0x1000 or base+len(code)>0xffffffff:
        raise UnsupportedGuestCode("source function RVA outside bounded range")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    insns=list(decoder.disasm(code,base))
    if not insns or len(insns)>MAX_INSNS or sum(x.size for x in insns)!=len(code):
        raise UnsupportedGuestCode("incomplete x86 disassembly or too many instructions")
    addresses={ins.address for ins in insns}
    if not any(ins.mnemonic=="ret" for ins in insns):
        raise UnsupportedGuestCode("source function contains no return")
    chunks=[]
    for ins in insns:
        pc=ins.address
        nxt=ins.address+ins.size
        ops=ins.operands
        mnemonic=ins.mnemonic
        lines=[]

        def memaddr(op):
            if op.type!=X86_OP_MEM:
                _unsupported(ins,"not a memory operand")
            if op.size not in (1,2,4,8) or op.mem.index!=0:
                _unsupported(ins,"only 8/16/32/64-bit nonindexed memory operands")
            if op.mem.base==0:
                _unsupported(ins,"memory operand without base")
            r=ins.reg_name(op.mem.base)
            if r not in REGS:
                _unsupported(ins,"unknown memory base")
            return "r[%d]+uint64_t(%d)"%(REGS[r],op.mem.disp)

        def val(op):
            if op.type==X86_OP_IMM:
                return "uint64_t(%d)"%op.imm
            if op.size not in (1,2,4,8):
                _unsupported(ins,"only 8/16/32/64-bit-width operands supported")
            if op.type==X86_OP_REG:
                r=ins.reg_name(op.reg)
                if r not in REGS:
                    _unsupported(ins,"register alias/width not supported")
                idx=REGS[r]
                if r in ("ah","bh","ch","dh"):
                    return "((r[%d]>>8)&0xffULL)"%idx
                if op.size==1:
                    return "(r[%d]&0xffULL)"%idx
                if op.size==2:
                    return "(r[%d]&0xffffULL)"%idx
                if op.size==4:
                    return "(r[%d]&0xffffffffULL)"%idx
                return "r[%d]"%idx
            if op.type==X86_OP_MEM:
                return "read%d(%s)"%(op.size*8,memaddr(op))
            _unsupported(ins,"unknown source operand")

        def assign(op,value):
            if op.size not in (1,2,4,8):
                _unsupported(ins,"only 8/16/32/64-bit write supported")
            if op.type==X86_OP_REG:
                r=ins.reg_name(op.reg)
                if r not in REGS:
                    _unsupported(ins,"register alias/width not supported")
                idx=REGS[r]
                if r in ("ah","bh","ch","dh"):
                    return "r[%d]=(r[%d]&~0xff00ULL)|(((uint64_t(%s))&0xffULL)<<8);"%(idx,idx,value)
                if op.size==1:
                    return "r[%d]=(r[%d]&~0xffULL)|((uint64_t(%s))&0xffULL);"%(idx,idx,value)
                if op.size==2:
                    return "r[%d]=(r[%d]&~0xffffULL)|((uint64_t(%s))&0xffffULL);"%(idx,idx,value)
                if op.size==4:
                    return "r[%d]=static_cast<uint64_t>(static_cast<uint32_t>(%s));"%(idx,value)
                return "r[%d]=%s;"%(idx,value)
            if op.type==X86_OP_MEM:
                return "write%d(%s,%s);"%(op.size*8,memaddr(op),value)
            _unsupported(ins,"invalid assignment target")

        if mnemonic in ("nop","endbr64"):
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic in ("mov","movabs"):
            if len(ops)!=2:
                _unsupported(ins,"mov operand count")
            lines.append("uint64_t rhs=%s;"%val(ops[1]))
            lines.append(assign(ops[0],"rhs"))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic in ("movzx","movsx","movsxd"):
            if len(ops)!=2 or ops[0].size not in (4,8):
                _unsupported(ins,"integer extension operand count/destination width")
            source_width=ops[1].size
            if mnemonic=="movsxd":
                if source_width!=4 or ops[0].size!=8:
                    _unsupported(ins,"movsxd requires 32->64 bits")
                signedtype="int32_t"
                target="uint64_t(int64_t(%s))"
            elif mnemonic=="movzx":
                if source_width not in (1,2):
                    _unsupported(ins,"movzx requires byte/word source")
                signedtype=None
            else:
                if source_width not in (1,2):
                    _unsupported(ins,"movsx requires byte/word source")
                signedtype="int8_t" if source_width==1 else "int16_t"
            lines.append("uint64_t rhs=%s;"%val(ops[1]))
            if signedtype:
                cast="uint64_t(int64_t(%s(rhs)))"%signedtype
                lines.append(assign(ops[0],cast))
            else:
                lines.append(assign(ops[0],"rhs"))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic=="lea":
            if len(ops)!=2 or ops[1].type!=X86_OP_MEM:
                _unsupported(ins,"lea shape")
            lines.append(assign(ops[0],memaddr(ops[1])))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic in ("add","sub","xor","and","or","cmp","test"):
            if len(ops)!=2:
                _unsupported(ins,"binary arithmetic operand count")
            if ops[0].type==X86_OP_IMM:
                _unsupported(ins,"arithmetic destination is immediate")
            width=ops[0].size
            if width not in (1,2,4,8):
                _unsupported(ins,"arithmetic width not yet supported")
            mask={1:"0xffULL",2:"0xffffULL",4:"0xffffffffULL",
                  8:"0xffffffffffffffffULL"}[width]
            sign={1:"0x80ULL",2:"0x8000ULL",4:"0x80000000ULL",
                  8:"0x8000000000000000ULL"}[width]
            lines.append("constexpr uint64_t MASK=%s,SIGNBIT=%s;"%(mask,sign))
            lines.append("uint64_t lhs=(%s)&MASK;"%val(ops[0]))
            lines.append("uint64_t rhs=(%s)&MASK;"%val(ops[1]))
            if mnemonic=="add":
                lines.append("uint64_t value=(lhs+rhs)&MASK;")
                lines.append("cf=(value<lhs);")
                lines.append("of=(((~(lhs^rhs))&(lhs^value)&SIGNBIT)!=0);")
            elif mnemonic in ("sub","cmp"):
                lines.append("uint64_t value=(lhs-rhs)&MASK;")
                lines.append("cf=(lhs<rhs);")
                lines.append("of=((((lhs^rhs)&(lhs^value))&SIGNBIT)!=0);")
            elif mnemonic in ("xor","and","or","test"):
                op={"xor":"^","and":"&","or":"|","test":"&"}[mnemonic]
                lines.append("uint64_t value=(lhs%s rhs)&MASK;"%op)
                lines.append("cf=false; of=false;")
            lines.append("zf=(value==0);sf=((value&SIGNBIT)!=0);")
            if mnemonic not in ("cmp","test"):
                lines.append(assign(ops[0],"value"))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic in ("inc","dec"):
            if len(ops)!=1:
                _unsupported(ins,"unary arithmetic operand count")
            width=ops[0].size
            if width not in (1,2,4,8):
                _unsupported(ins,"inc/dec width not supported")
            mask={1:"0xffULL",2:"0xffffULL",4:"0xffffffffULL",
                  8:"0xffffffffffffffffULL"}[width]
            sign={1:"0x80ULL",2:"0x8000ULL",4:"0x80000000ULL",
                  8:"0x8000000000000000ULL"}[width]
            signedmax={1:"0x7fULL",2:"0x7fffULL",4:"0x7fffffffULL",
                       8:"0x7fffffffffffffffULL"}[width]
            lines.append("constexpr uint64_t MASK=%s,SIGNBIT=%s;"%(mask,sign))
            lines.append("uint64_t lhs=(%s)&MASK;"%val(ops[0]))
            lines.append("uint64_t value=(lhs%s1ULL)&MASK;"%("+" if mnemonic=="inc" else "-"))
            lines.append("of=(lhs==%s);"% (signedmax if mnemonic=="inc" else sign))
            lines.append("zf=(value==0);sf=((value&SIGNBIT)!=0);")
            lines.append(assign(ops[0],"value"))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic=="push":
            if len(ops)!=1 or (ops[0].type!=X86_OP_IMM and ops[0].size!=8):
                _unsupported(ins,"push requires immediate or 64-bit operand")
            lines.append("uint64_t value=%s;"%val(ops[0]))
            lines.append("r[4]-=8ULL;write64(r[4],value);")
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic=="pop":
            if len(ops)!=1 or ops[0].type!=X86_OP_REG or ops[0].size!=8:
                _unsupported(ins,"pop requires 64-bit register")
            lines.append("uint64_t value=read64(r[4]);r[4]+=8ULL;")
            lines.append(assign(ops[0],"value"))
            lines.append("pc=0x%xULL;"%nxt)
        elif mnemonic=="ret":
            if len(ops)!=0:
                _unsupported(ins,"ret imm16 stack cleanup not supported")
            lines.append("uint64_t target=read64(r[4]);r[4]+=8ULL;")
            lines.append("if(target==STOP)return r[0];")
            lines.append("pc=target;")
        elif mnemonic=="call" or mnemonic=="jmp" or mnemonic in JCC:
            if len(ops)!=1 or ops[0].type!=X86_OP_IMM:
                _unsupported(ins,"only local direct branch/call")
            target=ops[0].imm
            if target not in addresses:
                _unsupported(ins,"target outside local function (no unresolved calls)")
            if mnemonic=="call":
                lines.append("r[4]-=8ULL;write64(r[4],0x%xULL);"%nxt)
                lines.append("pc=0x%xULL;"%target)
            elif mnemonic=="jmp":
                lines.append("pc=0x%xULL;"%target)
            else:
                lines.append("pc=(%s)?0x%xULL:0x%xULL;"%(JCC[mnemonic],target,nxt))
        else:
            _unsupported(ins,"opcode not in verified x86-to-AArch64 source subset")

        chunks.append("    case 0x%xULL: { %s break; }"%(pc," ".join(lines)))
    source=StringSource(chunks,base,len(insns))
    return Lifted(entry=base,insn_count=len(insns),code=source)

def StringSource(cases,entry,n):
    return """
// Generated at build-time from supported x86-64 instruction semantics.
// The resulting AArch64 executable contains NO x86 code/decoder/runtime.
#include <cstdint>
#include <array>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <limits>
static uint64_t run(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    constexpr uint64_t SIGN=0x8000000000000000ULL;
    constexpr uint64_t STOP=0xffffffffffffffffULL;
    constexpr uint64_t STACK=0x100000000ULL;
    std::array<uint8_t,8192> memory{};
    std::array<uint64_t,16> r{};
    r[1]=a; r[2]=b; r[8]=c; r[9]=d; // Windows x64 ABI
    r[4]=STACK+memory.size()-64;
    auto read64=[&](uint64_t address)->uint64_t {
        if(address<STACK||address-STACK>memory.size()-8)
            throw std::runtime_error("guest stack read outside bounds");
        uint64_t x=0;
        std::memcpy(&x,&memory[size_t(address-STACK)],8);
        return x;
    };
    auto write64=[&](uint64_t address,uint64_t value) {
        if(address<STACK||address-STACK>memory.size()-8)
            throw std::runtime_error("guest stack write outside bounds");
        std::memcpy(&memory[size_t(address-STACK)],&value,8);
    };
    auto read8=[&](uint64_t address)->uint64_t {
        if(address<STACK||address-STACK>memory.size()-1)
            throw std::runtime_error("guest stack read8 outside bounds");
        return uint64_t(memory[size_t(address-STACK)]);
    };
    auto read16=[&](uint64_t address)->uint64_t {
        if(address<STACK||address-STACK>memory.size()-2)
            throw std::runtime_error("guest stack read16 outside bounds");
        uint16_t x=0;
        std::memcpy(&x,&memory[size_t(address-STACK)],2);
        return uint64_t(x);
    };
    auto write8=[&](uint64_t address,uint64_t value) {
        if(address<STACK||address-STACK>memory.size()-1)
            throw std::runtime_error("guest stack write8 outside bounds");
        memory[size_t(address-STACK)]=uint8_t(value);
    };
    auto write16=[&](uint64_t address,uint64_t value) {
        if(address<STACK||address-STACK>memory.size()-2)
            throw std::runtime_error("guest stack write16 outside bounds");
        uint16_t x=uint16_t(value);
        std::memcpy(&memory[size_t(address-STACK)],&x,2);
    };
    auto read32=[&](uint64_t address)->uint64_t {
        if(address<STACK||address-STACK>memory.size()-4)
            throw std::runtime_error("guest stack read32 outside bounds");
        uint32_t x=0;
        std::memcpy(&x,&memory[size_t(address-STACK)],4);
        return uint64_t(x);
    };
    auto write32=[&](uint64_t address,uint64_t value) {
        if(address<STACK||address-STACK>memory.size()-4)
            throw std::runtime_error("guest stack write32 outside bounds");
        uint32_t x=uint32_t(value);
        std::memcpy(&memory[size_t(address-STACK)],&x,4);
    };
    write64(r[4],STOP);
    bool zf=false,sf=false,of=false,cf=false;
    uint64_t pc=%dULL;
    for(unsigned steps=0;steps<100000;steps++) {
      switch(pc) {
%s
        default: throw std::runtime_error("unsupported PC or indirect jump");
      }
    }
    throw std::runtime_error("guest step budget reached");
}
// Export a real Android NDK-compatible ARM64 library ABI. Building this
// from synthetic bytes validates AOT -> Android ELF, NOT CarX gameplay.
extern "C" __attribute__((visibility("default")))
uint64_t carx_aot_run_u64(uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    return run(a,b,c,d);
}
#ifndef CARX_AOT_LIBRARY_ONLY
int main(int argc,char** argv) {
    if(argc!=5)return 2;
    try {
        uint64_t a=strtoull(argv[1],nullptr,0);
        uint64_t b=strtoull(argv[2],nullptr,0);
        uint64_t c=strtoull(argv[3],nullptr,0);
        uint64_t d=strtoull(argv[4],nullptr,0);
        std::cout<<run(a,b,c,d)<<"\\n";
    } catch(const std::exception& e) {
        std::cerr<<e.what()<<"\\n";return 3;
    }
}
#endif // CARX_AOT_LIBRARY_ONLY
"""%(entry,"\n".join(cases))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input",type=Path,help="owned x86-64 function bytes, not full PC game")
    ap.add_argument("output",type=Path,help="C++ translated function")
    ap.add_argument("--base",type=lambda v:int(v,0),default=0x1000)
    ap.add_argument("--json",type=Path,default=None)
    args=ap.parse_args()
    result=lift_function(args.input.read_bytes(),args.base)
    args.output.write_text(result.code,encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps({
            "schema":"rm11carx.x64-function-static-recompilation.v1",
            "original_source_instruction_count":result.insn_count,
            "aarch64_code_emitted":False,
            "cpp_generated":True,
            "generated_from_user_binary_code_without_game_engine_deps":True,
            "original_carx_game_code_executed":False,
            "port_proven":False,
        },indent=2)+"\n",encoding="utf-8")

if __name__=="__main__":
    main()
