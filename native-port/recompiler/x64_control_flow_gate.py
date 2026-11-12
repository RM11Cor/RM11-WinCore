#!/usr/bin/env python3
"""Reachability-first x86-64 control-flow validation for original CarX PE snippets.

Disassembles only reachable instructions and emits structural metadata; no
game bytes, source disassembly or operands are printed. A basic block with
an external CALL, unresolved branch, data dependency or omitted parent
section is not an independently callable IL2CPP method.

This is a control-flow analysis gate, NOT a CPU emulator or native Android
game code runtime. Synthetic negative tests must pass before attempting
real original GameAssembly function AOT.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

MAX_CODE_BYTES=65536
MAX_REACHABLE_INSNS=4096
MAX_EDGES=8192
JCC_PREFIXES=("j",)
TRAPS={"int3","int","ud2","hlt","syscall","sysenter","icebp","into"}
UNCONDITIONAL={"jmp","ljmp"}
RETURNS={"ret","retf","iret","iretq"}
UNHANDLED_CONTROL={"loop","loope","loopne","loopnz","loopz","jrcxz","jecxz","jcxz"}

@dataclass(frozen=True)
class CfgResult:
    base:int
    byte_length:int
    reachable_instruction_count:int
    basic_block_count:int
    local_direct_calls:int
    external_direct_calls:int
    indirect_calls:int
    local_branches:int
    external_branches:int
    indirect_branches:int
    rip_relative_memory_instructions:int
    rip_target_outside_sample:int
    trap_instructions:int
    return_instructions:int
    decode_failures:int
    overlapping_decode_attempts:int
    unexpected_fallthrough_exits:int
    reachable_bytes:int
    unreachable_bytes:int
    no_unresolved_control_flow:bool
    structurally_self_contained_candidate:bool
    not_proven_callable_game_method:bool=True

    def safe_report(self)->dict[str,Any]:
        return {
            "schema":"rm11carx.x64-original-function-reachable-cfg.v1",
            "sample_base_rva_hex":hex(self.base),
            "sample_byte_length":self.byte_length,
            "reachable_instruction_count":self.reachable_instruction_count,
            "basic_block_count":self.basic_block_count,
            "local_direct_calls":self.local_direct_calls,
            "external_direct_calls":self.external_direct_calls,
            "indirect_calls":self.indirect_calls,
            "local_branches":self.local_branches,
            "external_branches":self.external_branches,
            "indirect_branches":self.indirect_branches,
            "rip_relative_memory_instructions":self.rip_relative_memory_instructions,
            "rip_target_outside_sample":self.rip_target_outside_sample,
            "trap_instructions":self.trap_instructions,
            "return_instructions":self.return_instructions,
            "decode_failures":self.decode_failures,
            "overlapping_decode_attempts":self.overlapping_decode_attempts,
            "unexpected_fallthrough_exits":self.unexpected_fallthrough_exits,
            "reachable_bytes":self.reachable_bytes,
            "unreachable_bytes":self.unreachable_bytes,
            "no_unresolved_control_flow":self.no_unresolved_control_flow,
            "structurally_self_contained_candidate":self.structurally_self_contained_candidate,
            "original_carx_gameplay_method_identity_proven":False,
            "reference_x86_execution_proven":False,
            "android_arm64_execution_proven":False,
            "original_game_first_frame_proven":False,
            "report_omits_source_code_bytes_and_instruction_operands":True,
        }

def inspect_cfg(code:bytes,base:int=0x1000)->CfgResult:
    if not isinstance(code,bytes) or not (1<=len(code)<=MAX_CODE_BYTES):
        raise ValueError("source bytes outside 1..65536 bound")
    if base<0x1000 or base+len(code)>0x100000000:
        raise ValueError("sample RVA outside 32-bit Windows PE address space")
    end=base+len(code)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    pending=deque([base])
    queued={base}
    decoded={}
    owned_by={}   # byte RVA -> instruction entry RVA
    starts={base}
    counters=Counter()
    edges=0

    def schedule(address:int,branch:bool=False)->None:
        nonlocal edges
        edges+=1
        if edges>MAX_EDGES:
            raise ValueError("excessive local code CFG edge expansion")
        if not (base<=address<end):
            counters["unexpected_fallthrough_exits"]+=1
            return
        if branch:
            starts.add(address)
        if address not in queued:
            pending.append(address)
            queued.add(address)

    while pending:
        pc=pending.popleft()
        if pc in decoded:
            continue
        if pc in owned_by and owned_by[pc]!=pc:
            counters["overlapping_decode_attempts"]+=1
            continue
        if len(decoded)>=MAX_REACHABLE_INSNS:
            raise ValueError("reachability CFG exceeds instruction limit")
        offset=pc-base
        ins=next(decoder.disasm(code[offset:],pc,count=1),None)
        if ins is None or not ins.size or pc+ins.size>end:
            counters["decode_failures"]+=1
            continue
        if any((pc+i) in owned_by and owned_by[pc+i]!=pc
               for i in range(ins.size)):
            counters["overlapping_decode_attempts"]+=1
            continue
        for i in range(ins.size):
            owned_by[pc+i]=pc
        decoded[pc]=ins

        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                counters["rip_relative_memory_instructions"]+=1
                target=pc+ins.size+op.mem.disp
                if not (base<=target<end):
                    counters["rip_target_outside_sample"]+=1
        op=ins.mnemonic.lower()
        next_pc=pc+ins.size
        if op in RETURNS:
            counters["return_instructions"]+=1
            continue
        if op in TRAPS:
            counters["trap_instructions"]+=1
            continue
        if op in UNHANDLED_CONTROL:
            counters["indirect_branches"]+=1
            # A loop/JRCXZ is not validated as normal fallthrough
            continue

        if op=="call" or op in UNCONDITIONAL or op.startswith(JCC_PREFIXES):
            direct=len(ins.operands)==1 and ins.operands[0].type==X86_OP_IMM
            target=ins.operands[0].imm if direct else None
            is_call=op=="call"
            is_unconditional=op in UNCONDITIONAL
            if is_call:
                if direct:
                    if base<=target<end:
                        counters["local_direct_calls"]+=1
                        schedule(target,branch=True)
                    else:
                        counters["external_direct_calls"]+=1
                else:
                    counters["indirect_calls"]+=1
                schedule(next_pc,branch=True)
            elif is_unconditional:
                if direct:
                    if base<=target<end:
                        counters["local_branches"]+=1
                        schedule(target,branch=True)
                    else:
                        counters["external_branches"]+=1
                else:
                    counters["indirect_branches"]+=1
            else:
                if direct:
                    if base<=target<end:
                        counters["local_branches"]+=1
                        schedule(target,branch=True)
                    else:
                        counters["external_branches"]+=1
                else:
                    counters["indirect_branches"]+=1
                schedule(next_pc,branch=True)
            continue
        schedule(next_pc)

    reachable_bytes=len(owned_by)
    unresolved=any(counters[k]>0 for k in (
        "external_direct_calls","indirect_calls","external_branches",
        "indirect_branches","decode_failures","overlapping_decode_attempts",
        "unexpected_fallthrough_exits","trap_instructions"
    ))
    # A sample can be control-flow-local yet rely on original Win64 global
    # memory, PE relocations, stack convention, or engine initialization.
    self_contained=(not unresolved and counters["return_instructions"]>0
                    and counters["rip_relative_memory_instructions"]==0
                    and reachable_bytes==len(code))
    return CfgResult(
        base=base,byte_length=len(code),reachable_instruction_count=len(decoded),
        basic_block_count=len(starts & decoded.keys()),
        local_direct_calls=counters["local_direct_calls"],
        external_direct_calls=counters["external_direct_calls"],
        indirect_calls=counters["indirect_calls"],
        local_branches=counters["local_branches"],
        external_branches=counters["external_branches"],
        indirect_branches=counters["indirect_branches"],
        rip_relative_memory_instructions=counters["rip_relative_memory_instructions"],
        rip_target_outside_sample=counters["rip_target_outside_sample"],
        trap_instructions=counters["trap_instructions"],
        return_instructions=counters["return_instructions"],
        decode_failures=counters["decode_failures"],
        overlapping_decode_attempts=counters["overlapping_decode_attempts"],
        unexpected_fallthrough_exits=counters["unexpected_fallthrough_exits"],
        reachable_bytes=reachable_bytes,
        unreachable_bytes=len(code)-reachable_bytes,
        no_unresolved_control_flow=not unresolved,
        structurally_self_contained_candidate=self_contained,
    )
