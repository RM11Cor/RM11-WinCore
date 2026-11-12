#!/usr/bin/env python3
"""Read-only 256 original source GameAssembly parent/child CFG analysis.

Requires owner-exported PortLab v1.3 ZIP containing independently SHA-256
verified original PE x86 child/parent bytes and correct original Win64
UNWIND_INFO/CHAININFO metadata. Never imports or executes game code,
never outputs raw guest bytes, operands or IL2CPP method names.

The Windows UNWIND chain is a *metadata relationship*, not proof of
machine-code control flow or complete original game methods.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
from zipfile import ZipFile

from analyze_carx_win64_xdata_zip import analyze
from x64_multisegment_cfg import inspect_multisegment_cfg

def owner_source_parent_child_cfg(source_zip:Path)->dict:
    upstream=analyze(source_zip)
    if not upstream["original_parent_code_archive_schema_v3"]:
        raise ValueError("requires original phone-export PortLab v1.3 parent-code ZIP")
    report={
        "schema":"rm11carx.user-owner-original-gameassembly-parent-child-cfg.v1",
        "source_zip_version":(
            "1.4-inter-region-executable-source-gaps"
            if upstream.get("original_executable_gap_archive_schema_v4")
            else "1.3-parent-code-bounded"),
        "raw_executable_gap_bytes_owner_source_verified":
            upstream.get("original_executable_gap_archive_schema_v4",False),
        "source_code_sha256_validated":True,
        "source_unwind_sha256_validated":True,
        "source_parent_code_sha256_validated":True,
        "verified_original_source_members":{
            "child_code_regions":upstream["sha256_verified_code_regions"],
            "unwind_metadata_unique":upstream["sha256_verified_unique_unwind_records"],
            "parent_code_unique":upstream["sha256_verified_unique_parent_code_fragments"],
            "parent_code_bytes":upstream["sha256_verified_unique_parent_code_bytes"],
        },
        "original_source_code_execution":False,
        "original_gameplay_method_identified":False,
        "original_carx_android_arm64_execution":False,
        "original_unity_gameplay_frame":False,
        "original_proprietary_code_in_report":False,
        "unwind_chain_not_a_control_flow_edge":True,
        "not_equivalent_to_a_whole_function_static_recompiler":True,
    }
    counters=Counter()
    per_function=[]
    with ZipFile(source_zip) as z:
        source=json.loads(z.read("manifest.json"))
        for f in source["functions"]:
            child_rva=f["relative_rva"]
            seg={child_rva:z.read(f["zip_member"])}
            chain=[]
            parents=[]
            for u in f["unwind_records"]:
                if "chained_runtime_function" not in u:
                    continue
                declaration=u.get("original_parent_code")
                if u.get("parent_code_status")!="EXPORTED_VERIFIED_BOUNDED_FRAGMENT" or \
                        not declaration:
                    # Analyzer already ensured missing member is explicitly
                    # classified; this group isn't ready for linked CFG.
                    chain=[]
                    break
                base=declaration["begin_rva"]
                code=z.read(declaration["zip_member"])
                if base in seg and seg[base]!=code:
                    raise ValueError("source parent RVA collides with child code")
                seg[base]=code
                parents.append(base)
                chain.append((base,declaration["end_rva"]))
            if len(parents)!=sum(1 for x in f["unwind_records"]
                                if x.get("chained_runtime_function")):
                counters["source_groups_with_missing_parent_bytes"]+=1
                continue
            gaps_mapped=0
            gaps_missing=0
            for gap in f.get("inter_region_gaps",[]):
                if gap.get("gap_source_status")==(
                        "EXPORTED_RAW_PE_EXECUTABLE_INTERVAL"):
                    begin=gap["begin_rva"]
                    raw=z.read(gap["zip_member"])
                    if begin in seg and seg[begin]!=raw:
                        raise ValueError("original interval-gap source RVA collision")
                    seg[begin]=raw
                    gaps_mapped+=1
                else:
                    gaps_missing+=1
            root=parents[-1] if parents else child_rva
            # Two *separate* entry experiments: entering a parent does
            # NOT imply that original execution naturally reaches child.
            cfg_root=inspect_multisegment_cfg(seg,[root])
            cfg_child=inspect_multisegment_cfg(seg,[child_rva])
            root_obstacles=(
                cfg_root.unmapped_direct_call_edges+
                cfg_root.unmapped_direct_branch_edges+
                cfg_root.indirect_call_edges+
                cfg_root.indirect_branch_edges+
                cfg_root.rip_relative_original_data_dependencies+
                cfg_root.truncated_x86_decode+
                cfg_root.instruction_overlap_conflicts+
                cfg_root.unmapped_fallthrough_edges+
                cfg_root.reachable_trap_instructions
            )
            mapped_cross_edges=(
                cfg_root.cross_segment_direct_branch_edges+
                cfg_root.cross_segment_direct_call_edges
            )
            counters["source_groups_verified"]+=1
            counters["source_groups_with_verified_raw_gap_bytes"]+=gaps_mapped>0
            counters["source_groups_with_missing_executable_gap_bytes"]+=gaps_missing>0
            counters["verified_raw_executable_gap_regions"]+=gaps_mapped
            counters["missing_raw_executable_gap_regions"]+=gaps_missing
            counters["groups_with_chained_parent_code"]+=bool(parents)
            counters["groups_with_cross_segment_x86_control_flow_from_root"]+=mapped_cross_edges>0
            counters["groups_with_unmapped_calls_from_root"]+=cfg_root.unmapped_direct_call_edges>0
            counters["groups_with_indirect_calls_from_root"]+=cfg_root.indirect_call_edges>0
            counters["groups_with_unmapped_branches_from_root"]+=cfg_root.unmapped_direct_branch_edges>0
            counters["groups_with_RIP_dependencies_from_root"]+=cfg_root.rip_relative_original_data_dependencies>0
            counters["groups_with_reachable_return_from_root"]+=cfg_root.reachable_ret_instructions>0
            counters["groups_with_no_source_local_RIP_or_control_obstacles"]+=root_obstacles==0
            counters["groups_with_unreachable_bytes_from_root"]+=cfg_root.unreachable_original_code_bytes>0
            per_function.append({
                "child_source_rva_hex":hex(child_rva),
                "parent_source_rvas_hex":[hex(x) for x in parents],
                "parent_metadata_chain_depth":len(parents),
                "verified_original_executable_gap_fragments":gaps_mapped,
                "missing_original_executable_gap_fragments":gaps_missing,
                "source_gap_contents_not_proven_owned_by_same_method":True,
                "root_source_entry_rva_hex":hex(root),
                "actual_root_entry_reachable_cfg":cfg_root.safe_report(),
                "original_child_entry_reachable_cfg":cfg_child.safe_report(),
                "mapped_cross_fragment_control_edges_from_root":mapped_cross_edges,
                "root_unresolved_dependency_count":root_obstacles,
                "verified_complete_unity_IL2CPP_gameplay_method":False,
            })
    per_function.sort(key=lambda x:(
        x["root_unresolved_dependency_count"],
        -x["mapped_cross_fragment_control_edges_from_root"],
        x["parent_metadata_chain_depth"],
        x["child_source_rva_hex"]
    ))
    report["source_group_stats"]=dict(sorted(counters.items()))
    report["ranked_original_source_candidate_structures"]=per_function
    report["next_action"]=(
        "Select one verified original root/child cross-range CFG and "
        "resolve its external x64 data/call/SEH dependencies. "
        "Prove original Windows x86 reference behavior before "
        "Android NDK AArch64 game execution claim."
    )
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("original_owner_zip",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    report=owner_source_parent_child_cfg(args.original_owner_zip)
    text=json.dumps(report,ensure_ascii=False,indent=2)+"\n"
    if args.out:
        if args.out.exists():
            raise ValueError("refuse to overwrite existing local original-source report")
        args.out.write_text(text,encoding="utf-8")
    else:print(text)
if __name__=="__main__":
    main()
