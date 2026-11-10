#!/usr/bin/env python3
"""Fail-closed handoff audit for immutable original GNU IFUNC native writer stages 122..124.

This is a STATIC source-contract regression test, never native hardware proof.
It prevents a stale previous-IFUNC address or writer ledger from being copied
into the genuine-source GDB watch, tamper control, shell runner or independent
replay assertions. Each intentionally corrupted copy must be rejected.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDICES = (122, 123, 124)


def require(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError("IFUNC source handoff FAIL-CLOSED: " + label)


def read(path: str) -> str:
    p = ROOT / path
    require(p.is_file() and not p.is_symlink(), "missing file " + path)
    return p.read_text()


def parameter(script: str, name: str) -> str:
    m = re.search(r"^" + name + r"=(0x[0-9a-f]+)$", script, re.M)
    require(m is not None, "missing unique " + name)
    require(len(re.findall(r"^" + name + r"=", script, re.M)) == 1, "duplicated " + name)
    return m.group(1)


def verify(index: int, files: dict[str, str], prior_target: str) -> None:
    ledger, previous, ordinal = index - 85, index - 86, index - 86
    validator = files["validator"]
    native = files["native"]
    workflow = files["workflow"]
    source_plan = files["source_plan"]
    require(f"INDEX={index}" in validator, f"{index} index")
    require(f'assert index=={index}' in source_plan, f"{index} original source index")
    target = parameter(validator, "TARGET")
    old = parameter(validator, "OLD")
    resolver = parameter(validator, "RESOLVER")
    require(target != prior_target, f"{index} target must differ from previous")
    require(f'r["table_index"]=={ordinal}' in validator
            or f'row["table_index"]=={ordinal}' in validator,
            f"{index} exact DT_JMPREL ordinal")
    require(f'aliases==[{index}]' in validator,
            f"{index} original resolver alias index")
    require(f'assert gdb.count("watch -location *(unsigned long long *){target}")==1'
            in validator, f"{index} independent source GDB hardware watch target")
    negative = [line for line in validator.splitlines()
                if '("hardware_watch_missing",' in line]
    require(len(negative) == 1 and f"{target}$" in negative[0]
            and prior_target not in negative[0],
            f"{index} negative control must corrupt THIS target's hardware watch")
    require("assert len(rejected)==10" in validator,
            f"{index} retain ten negative native corruption checks")
    require(f'assert prior["native_source_original_IFUNC{index-1}_distinct_writer_ledger_count"]=={previous}'
            in validator, f"{index} previous independent writer ledger")
    require(f'assert plan["verified_previous_unique_native_writer_ledger"]=={previous}'
            in validator, f"{index} independent planned previous ledger")
    require(f'"unique_original_libc_native_hardware_writer_target_count":{ledger}'
            in validator, f"{index} independent new writer count")
    require(f"assert p['candidate_source_index']=={index}" in native,
            f"{index} genuine native runner source index")
    require(f"assert p['candidate_original_table_index']=={ordinal}" in native,
            f"{index} genuine native runner original ELF table index")
    require(f"assert p['original_guest_resolver_entry']=='{resolver}'" in native,
            f"{index} genuine native runner resolver")
    require(f"assert p['original_guest_target']=='{target}'" in native,
            f"{index} genuine native runner current target")
    require(f"assert p['original_target_qword']=='{old}'" in native,
            f"{index} genuine native runner original old target value")
    require(f"assert p['verified_previous_unique_native_writer_ledger']=={previous}"
            in native, f"{index} genuine native runner previous writer ledger")
    require(f"assert plan['candidate_source_index']=={index}" in workflow,
            f"{index} strict independent CI source index")
    require(f"assert plan['original_guest_target']=='{target}'" in workflow,
            f"{index} strict independent CI target")
    require(f"assert plan['original_target_qword']=='{old}'" in workflow,
            f"{index} strict independent CI original value")
    require(f"assert proof['unique_original_libc_native_hardware_writer_target_count']=={ledger}"
            in workflow, f"{index} strict independent CI target count")
    require(f"assert data['native_source_original_IFUNC{index-1}_distinct_writer_ledger_count']=={previous}"
            in workflow, f"{index} strict CI prerequisite writer count")


def sabotage(index: int, files: dict[str, str], prior_target: str) -> None:
    target = parameter(files["validator"], "TARGET")
    ledger, previous = index - 85, index - 86
    tests = [
        ("wrong_GDB_target", "validator",
         f'assert gdb.count("watch -location *(unsigned long long *){target}")==1',
         f'assert gdb.count("watch -location *(unsigned long long *){prior_target}")==1'),
        ("wrong_native_target", "native",
         f"assert p['original_guest_target']=='{target}'",
         f"assert p['original_guest_target']=='{prior_target}'"),
        ("incorrect_writer_ledger", "workflow",
         f"assert proof['unique_original_libc_native_hardware_writer_target_count']=={ledger}",
         f"assert proof['unique_original_libc_native_hardware_writer_target_count']=={previous}"),
        ("incorrect_previous_ledger", "validator",
         f'assert prior["native_source_original_IFUNC{index-1}_distinct_writer_ledger_count"]=={previous}',
         f'assert prior["native_source_original_IFUNC{index-1}_distinct_writer_ledger_count"]=={previous-1}'),
        ("wrong_native_original_qword", "native",
         f"assert p['original_target_qword']=='{parameter(files['validator'], 'OLD')}'",
         "assert p['original_target_qword']=='0x1'"),
    ]
    for name, key, before, after in tests:
        require(before in files[key] and before != after, f"{index} sabotage setup {name}")
        mutated = dict(files)
        mutated[key] = files[key].replace(before, after, 1)
        try:
            verify(index, mutated, prior_target)
        except AssertionError:
            print("KERNIX_G0_WRITER_CONTRACT_REJECTED", index, name)
        else:
            raise AssertionError(f"FAIL OPEN: IFUNC{index} accepted stale handoff {name}")



def verify_return_candidate_contract(index: int, plan: str, native_ret: str) -> int:
    """The real native runtime must use exactly the source-disassembled RET set.

    This rejects the stale previous-stage candidate count BEFORE running FEX.
    """
    m = re.search(r"^RET_CANDIDATES=\(([^)\n]+)\)$", plan, re.M)
    require(m is not None, f"{index} missing exact source C3 RET tuple")
    candidates = re.findall(r"0x[0-9a-f]+", m.group(1))
    require(len(candidates) > 0 and len(candidates) == len(set(candidates)),
            f"{index} duplicate/empty C3 source candidates")
    count = len(candidates)
    require(f"assert source_ret['original_IFUNC_source_index']=={index} and len(actual)=={count}"
            in native_ret, f"{index} source x86 C3 RET count")
    require(f"assert len({{x['guest_source_RIP'] for x in actual}})=={count}"
            in native_ret, f"{index} distinct source x86 C3 RET count")
    require(f"assert len(p['original_source_RET_guest_RIP_candidates'])=={count}"
            in native_ret, f"{index} native FEX read plan candidate count")
    return count


def sabotage_return_candidate_contract(index: int, plan: str, native_ret: str) -> None:
    count = verify_return_candidate_contract(index, plan, native_ret)
    tests = [
        ("wrong_C3_source_count", f"and len(actual)=={count}",
         f"and len(actual)=={count+1}"),
        ("wrong_C3_unique_count",
         f"len({{x['guest_source_RIP'] for x in actual}})=={count}",
         f"len({{x['guest_source_RIP'] for x in actual}})=={count+1}"),
        ("wrong_FEX_plan_RET_count",
         f"len(p['original_source_RET_guest_RIP_candidates'])=={count}",
         f"len(p['original_source_RET_guest_RIP_candidates'])=={count+1}"),
    ]
    for name, before, after in tests:
        require(before in native_ret, f"{index} RET mutation setup {name}")
        forged = native_ret.replace(before, after, 1)
        try:
            verify_return_candidate_contract(index, plan, forged)
        except AssertionError:
            print("KERNIX_G0_WRITER_CONTRACT_REJECTED", index, name)
        else:
            raise AssertionError(f"FAIL OPEN: IFUNC{index} accepted wrong C3 RET count {name}")


def main() -> None:
    for index in INDICES:
        checker = read(f"native-engine/tools/kernix_g0_original_libc_ifunc{index}_distinct_native_writer_independent_gate.py")
        prev = read(f"native-engine/tools/kernix_g0_original_libc_ifunc{index-1}_distinct_native_writer_independent_gate.py")
        files = {
            "validator": checker,
            "native": read(f"native-engine/tools/kernix_g0_ifunc{index}_native_fex_writer_watch.sh"),
            "workflow": read(f".github/workflows/kernix-g0-original-libc-ifunc{index}-independent-native-writer-hw-replay.yml"),
            "source_plan": read(f"native-engine/tools/kernix_g0_original_libc_ifunc{index}_source_distinct_hw_watch_plan.py"),
        }
        prior_target = parameter(prev, "TARGET")
        verify(index, files, prior_target)
        sabotage(index, files, prior_target)
        ret_plan = read(f"native-engine/tools/kernix_g0_original_ifunc{index}_one_guest_dynamic_ret_hardware_plan.py")
        native_ret = read(f"native-engine/tools/kernix_g0_ifunc{index}_native_fex_call_ret_watch.sh")
        ret_count = verify_return_candidate_contract(index, ret_plan, native_ret)
        sabotage_return_candidate_contract(index, ret_plan, native_ret)
        print("KERNIX_G0_IFUNC_SOURCE_TO_NATIVE_WRITER_HANDOFF_STATIC_PASS", index, "C3_RET_COUNT", ret_count)
    print("KERNIX_G0_GNU_WRITER_CONTRACT_122_123_124_24_MUTATIONS_REJECTED_SOURCE_ONLY_NOT_HARDWARE_PROOF")


if __name__ == "__main__":
    main()
