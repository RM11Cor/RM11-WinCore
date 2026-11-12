#!/usr/bin/env python3
"""Bounded x64 reachable CFG across *disjoint* original PE executable ranges.

Allows static branch/call analysis across a child's RUNTIME_FUNCTION range
and its verified CHAININFO parent executable ranges. This is NOT a whole
Unity IL2CPP method or proof of Android execution. The parent pointers in
Win64 xdata describe unwind metadata and do not imply an x86 branch edge.

Outputs only structural metrics and RVA identifiers, never source x86 bytes,
instruction operands or disassembly. All source bytes stay owner-local.
"""
from __future__ import annotations
from collections import Counter,deque
from dataclasses import dataclass
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP

MAX_SEGMENTS=8
MAX_REGION_BYTES=4096
MAX_TOTAL_BYTES=8*4096
MAX_VISITED_INSTRUCTIONS=8192
MAX_EDGES=16384
UNCONDITIONAL={"jmp","ljmp"}
RETURNS={"ret","retf","iret","iretq"}
TRAPS={"int3","int","ud2","hlt","syscall","sysenter","icebp","into"}
NONTRIVIAL_CONTROL={"loop","loope","loopne","loopnz","loopz","jrcxz","jecxz","jcxz"}

@dataclass(frozen=True)
class MultiCfg:
    entry_rvas:tuple[int,...]
    segment_count:int
    total_source_bytes:int
    reachable_instructions:int
    reachable_original_code_bytes:int
    unreachable_original_code_bytes:int
    cross_segment_direct_call_edges:int
    cross_segment_direct_branch_edges:int
    local_direct_call_edges:int
    local_direct_branch_edges:int
    unmapped_direct_call_edges:int
    unmapped_direct_branch_edges:int
    indirect_call_edges:int
    indirect_branch_edges:int
    rip_relative_original_data_dependencies:int
    unmapped_rip_relative_targets:int
    reachable_ret_instructions:int
    reachable_trap_instructions:int
    truncated_x86_decode:int
    instruction_overlap_conflicts:int
    unmapped_fallthrough_edges:int
    source_region_entry_points_not_a_verified_method:bool=True

    def safe_report(self):
        return {
            "schema":"rm11carx.original-x64-multisegment-reachable-cfg.v1",
            "entry_rvas_hex":[hex(r) for r in self.entry_rvas],
            "segment_count":self.segment_count,
            "original_executable_source_bytes":self.total_source_bytes,
            "reachable_instructions":self.reachable_instructions,
            "reachable_code_bytes":self.reachable_original_code_bytes,
            "unreachable_code_bytes":self.unreachable_original_code_bytes,
            "cross_segment_direct_call_edges":self.cross_segment_direct_call_edges,
            "cross_segment_direct_branch_edges":self.cross_segment_direct_branch_edges,
            "local_direct_call_edges":self.local_direct_call_edges,
            "local_direct_branch_edges":self.local_direct_branch_edges,
            "unmapped_direct_call_edges":self.unmapped_direct_call_edges,
            "unmapped_direct_branch_edges":self.unmapped_direct_branch_edges,
            "indirect_call_edges":self.indirect_call_edges,
            "indirect_branch_edges":self.indirect_branch_edges,
            "rip_relative_original_data_dependencies":
                self.rip_relative_original_data_dependencies,
            "unmapped_rip_relative_targets":self.unmapped_rip_relative_targets,
            "reachable_ret_instructions":self.reachable_ret_instructions,
            "reachable_trap_instructions":self.reachable_trap_instructions,
            "truncated_x86_decode":self.truncated_x86_decode,
            "instruction_overlap_conflicts":self.instruction_overlap_conflicts,
            "unmapped_fallthrough_edges":self.unmapped_fallthrough_edges,
            "unwind_chain_is_not_proof_of_control_flow_connection":True,
            "source_region_entry_points_not_a_verified_method":True,
            "actual_original_carx_code_executed":False,
            "actual_android_arm64_gamecode_executed":False,
            "proprietary_machine_code_emitted":False,
        }

def inspect_multisegment_cfg(segments:dict[int,bytes],
                             entry_rvas:list[int]|tuple[int,...])->MultiCfg:
    if not isinstance(segments,dict) or not(1<=len(segments)<=MAX_SEGMENTS):
        raise ValueError("original executable source segment count outside 1..8")
    if not entry_rvas or len(entry_rvas)>MAX_SEGMENTS:
        raise ValueError("source entry list missing/excessive")
    spans=[]
    total=0
    for base,code in sorted(segments.items()):
        if not isinstance(base,int) or not isinstance(code,bytes):
            raise ValueError("source executable requires original RVA and immutable bytes")
        if base<0x1000 or not(1<=len(code)<=MAX_REGION_BYTES) or \
                base+len(code)>0x100000000:
            raise ValueError("source PE RVA or original region size invalid")
        if spans and base<spans[-1][1]:
            raise ValueError("overlapping source PE function fragments")
        spans.append((base,base+len(code),code))
        total+=len(code)
    if total>MAX_TOTAL_BYTES:
        raise ValueError("source code group over total bounded size")

    def locate(address:int):
        for base,end,code in spans:
            if base<=address<end:return base,end,code
        return None

    entries=tuple(dict.fromkeys(entry_rvas))
    if any(locate(x) is None for x in entries):
        raise ValueError("entry RVA is not in verified source executable segments")

    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    pending=deque(entries)
    queued=set(entries)
    seen=set()
    occupied={}  # global RVA -> first instruction start RVA
    counters=Counter()
    n_edges=0

    def schedule(target,origin,kind):
        nonlocal n_edges
        n_edges+=1
        if n_edges>MAX_EDGES:
            raise ValueError("source PE CFG edge expansion limit")
        place=locate(target)
        if place is None:
            counters["unmapped_"+kind+"_edges"]+=1
            return
        if kind in ("direct_call","direct_branch"):
            local=target>=origin[0] and target<origin[1]
            counters[("local_" if local else "cross_segment_")+kind+"_edges"]+=1
        if target not in queued:
            queued.add(target)
            pending.append(target)

    while pending:
        pc=pending.popleft()
        if pc in seen:continue
        origin=locate(pc)
        if origin is None:
            counters["unmapped_fallthrough_edges"]+=1
            continue
        if pc in occupied and occupied[pc]!=pc:
            counters["instruction_overlap_conflicts"]+=1
            continue
        if len(seen)>=MAX_VISITED_INSTRUCTIONS:
            raise ValueError("source PE CFG instruction budget")
        base,end,code=origin
        instruction=next(decoder.disasm(code[pc-base:],pc,count=1),None)
        if instruction is None or not instruction.size or pc+instruction.size>end:
            counters["truncated_x86_decode"]+=1
            continue
        if any(addr in occupied and occupied[addr]!=pc
               for addr in range(pc,pc+instruction.size)):
            counters["instruction_overlap_conflicts"]+=1
            continue
        for addr in range(pc,pc+instruction.size):
            occupied[addr]=pc
        seen.add(pc)
        nxt=pc+instruction.size
        for operand in instruction.operands:
            if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                counters["rip_relative_original_data_dependencies"]+=1
                target=nxt+operand.mem.disp
                if locate(target) is None:
                    counters["unmapped_rip_relative_targets"]+=1
        op=instruction.mnemonic.lower()
        if op in RETURNS:
            counters["reachable_ret_instructions"]+=1
            continue
        if op in TRAPS:
            counters["reachable_trap_instructions"]+=1
            continue
        if op in NONTRIVIAL_CONTROL:
            counters["indirect_branch_edges"]+=1
            continue
        is_call=op=="call"
        is_jump=op in UNCONDITIONAL
        is_conditional=op.startswith("j") and not is_jump
        if is_call or is_jump or is_conditional:
            direct=(len(instruction.operands)==1 and
                    instruction.operands[0].type==X86_OP_IMM)
            if direct:
                target=instruction.operands[0].imm
                schedule(target,origin,
                         "direct_call" if is_call else "direct_branch")
            else:
                counters["indirect_call_edges" if is_call else
                         "indirect_branch_edges"]+=1
            if is_call or is_conditional:
                schedule(nxt,origin,"fallthrough")
            continue
        schedule(nxt,origin,"fallthrough")

    return MultiCfg(
        entry_rvas=entries,
        segment_count=len(segments),
        total_source_bytes=total,
        reachable_instructions=len(seen),
        reachable_original_code_bytes=len(occupied),
        unreachable_original_code_bytes=total-len(occupied),
        cross_segment_direct_call_edges=counters["cross_segment_direct_call_edges"],
        cross_segment_direct_branch_edges=counters["cross_segment_direct_branch_edges"],
        local_direct_call_edges=counters["local_direct_call_edges"],
        local_direct_branch_edges=counters["local_direct_branch_edges"],
        unmapped_direct_call_edges=counters["unmapped_direct_call_edges"],
        unmapped_direct_branch_edges=counters["unmapped_direct_branch_edges"],
        indirect_call_edges=counters["indirect_call_edges"],
        indirect_branch_edges=counters["indirect_branch_edges"],
        rip_relative_original_data_dependencies=
            counters["rip_relative_original_data_dependencies"],
        unmapped_rip_relative_targets=counters["unmapped_rip_relative_targets"],
        reachable_ret_instructions=counters["reachable_ret_instructions"],
        reachable_trap_instructions=counters["reachable_trap_instructions"],
        truncated_x86_decode=counters["truncated_x86_decode"],
        instruction_overlap_conflicts=counters["instruction_overlap_conflicts"],
        unmapped_fallthrough_edges=counters["unmapped_fallthrough_edges"],
    )
