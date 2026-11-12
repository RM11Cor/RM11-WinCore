#!/usr/bin/env python3
"""Evidence-based Win64 source-function admission prior to Android AOT.

Combines actual PE .pdata entry boundaries, verified .xdata/CHAININFO
and reachable x86 CFG. A small exception-table fragment may belong
to a parent method; a RET or a successful unwind parse alone does
NOT prove independent original IL2CPP gameplay function identity.

Safe result includes only structure and bounded RVA identifiers.
No proprietary code bytes or source disassembly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from win64_unwind_boundary import UnwindRecord
from x64_control_flow_gate import CfgResult

MAX_ADMISSION_CODE_BYTES=65536
MAX_RECORD_CHAIN=4
MAX_GUEST_STACK_BYTES=8192

@dataclass(frozen=True)
class SourceAdmission:
    source_rva:int
    source_bytes:int
    status:str
    first_blocker:str|None
    blockers:tuple[str,...]
    source_code_reachable_bytes:int
    unwind_record_count:int
    contains_chained_parent:bool
    approximate_unwind_stack_bytes:int
    # These may not be inferred by PE metadata or CFG alone:
    confirmed_original_il2cpp_method:bool=False
    confirmed_reference_behavior:bool=False
    confirmed_android_arm64_game_execution:bool=False
    confirmed_real_carx_frame:bool=False

    def safe_report(self)->dict[str,Any]:
        return {
            "schema":"rm11carx.win64-unwind-plus-reachable-cfg-admission.v1",
            "source_rva_hex":hex(self.source_rva),
            "source_code_bytes":self.source_bytes,
            "status":self.status,
            "first_blocker":self.first_blocker,
            "blockers":list(self.blockers),
            "source_code_reachable_bytes":self.source_code_reachable_bytes,
            "unwind_record_count":self.unwind_record_count,
            "contains_chained_parent":self.contains_chained_parent,
            "approximate_unwind_stack_bytes":self.approximate_unwind_stack_bytes,
            "confirmed_original_il2cpp_method":False,
            "confirmed_reference_behavior":False,
            "confirmed_android_arm64_game_execution":False,
            "confirmed_real_carx_frame":False,
        }

def evaluate_win64_source_function(
    source_rva:int,
    source_length:int,
    cfg:CfgResult,
    unwind_chain:list[UnwindRecord],
    manifest_status:str,
) -> SourceAdmission:
    if not (0x1000<=source_rva<2**32 and
            1<=source_length<=MAX_ADMISSION_CODE_BYTES and
            source_rva+source_length<=2**32):
        raise ValueError("Win64 source function bounds invalid")
    if (cfg.base,cfg.byte_length)!=(source_rva,source_length):
        raise ValueError("source Win64 CFG/sample RVA or length mismatch")
    if len(unwind_chain)>MAX_RECORD_CHAIN:
        raise ValueError("Win64 source unwind chain over allowed depth")
    if any(not isinstance(x,UnwindRecord) for x in unwind_chain):
        raise ValueError("Win64 source metadata must be independently decoded")
    if not isinstance(manifest_status,str):
        raise ValueError("missing original Win64 source status")

    blockers=[]
    # Original PE owner-export .xdata may be incomplete, even if the
    # first record was independently decoded.
    complete=(manifest_status=="COMPLETE_UNWIND_CHAIN_READ")
    if not complete or not unwind_chain:
        blockers.append("source_unwind_chain_incomplete_or_unverified")
    has_parent=any(x.chained_runtime_function is not None for x in unwind_chain)
    if has_parent:
        # The original sample is a .pdata range; CHAININFO describes a
        # parent RUNTIME_FUNCTION, NOT an automatic merged function body.
        blockers.append("chained_parent_source_function_body_not_exported")
    if complete and unwind_chain and unwind_chain[-1].chained_runtime_function:
        blockers.append("last_unwind_record_still_chained")
    if unwind_chain and unwind_chain[0].prologue_bytes>source_length:
        blockers.append("source_unwind_prologue_longer_than_fragment")
    if any(x.handler_rva is not None for x in unwind_chain):
        blockers.append("win64_exception_handler_dependency_unresolved")
    estimated_stack=sum(x.stack_bytes_deallocated_by_unwind for x in unwind_chain)
    if estimated_stack>MAX_GUEST_STACK_BYTES:
        blockers.append("original_win64_stack_exceeds_current_aot_guest_memory")
    if cfg.decode_failures or cfg.overlapping_decode_attempts:
        blockers.append("reachable_x64_instruction_boundary_conflict")
    if cfg.external_direct_calls or cfg.indirect_calls:
        blockers.append("original_external_or_indirect_call_dependencies")
    if cfg.external_branches or cfg.indirect_branches:
        blockers.append("original_unresolved_branch_dependencies")
    if cfg.rip_relative_memory_instructions:
        blockers.append("original_PE_RIP_relative_data_or_relocation_dependency")
    if cfg.trap_instructions or cfg.unexpected_fallthrough_exits:
        blockers.append("source_trap_or_incomplete_fallthrough")
    if not cfg.return_instructions:
        blockers.append("no_reachable_return_from_source_entry")
    if cfg.unreachable_bytes:
        blockers.append("unreachable_code_or_padding_in_source_region")
    if not cfg.no_unresolved_control_flow and not any(
            x in blockers for x in (
                "reachable_x64_instruction_boundary_conflict",
                "original_external_or_indirect_call_dependencies",
                "original_unresolved_branch_dependencies",
                "source_trap_or_incomplete_fallthrough",
            )):
        blockers.append("other_unresolved_original_control_flow")

    # Avoid false "pass": even a complete, dependency-local Win64
    # source region must undergo method identity, real x86 reference
    # behavior and actual ARM64 device execution.
    status="STRUCTURALLY_LOCAL_CANDIDATE_NEEDS_REFERENCE_EXECUTION"
    if blockers:
        status="BLOCKED_SOURCE_DEPENDENCIES_OR_INCOMPLETE_BOUNDARY"
    return SourceAdmission(
        source_rva=source_rva,
        source_bytes=source_length,
        status=status,
        first_blocker=blockers[0] if blockers else None,
        blockers=tuple(blockers),
        source_code_reachable_bytes=cfg.reachable_bytes,
        unwind_record_count=len(unwind_chain),
        contains_chained_parent=has_parent,
        approximate_unwind_stack_bytes=estimated_stack,
    )
