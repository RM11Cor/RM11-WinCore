#!/usr/bin/env python3
"""Fail-closed real FEX Linux ARM64 IFUNC102 original C3 RET native-read attestation.

NEVER infer a guest RET memory read solely from its original x86 bytes,
a JIT header, the source-only GDB script, or arrival at the return site.
Accept only a hardware READ watchpoint and the following caller/store chain
observed in ONE new real FEX process. No Android / Wine / game proof.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

LIBC_SHA = "7e262ac92a454f36664b9c95a8927ecc4fb0f0f007206c2613b1e9ce14e76906"
LDSO_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
RET = 0x8040b4f27
SLOT = 0x80300f9b8
RETURN = 0x80100fd5c
RESOLVER = 0x8040b4f00
STORE = 0x80100fd60
TARGET = 0x804202d78
OLD = 0x283d0
NEW = 0x8040c74a0
LOG = "original-libc-IFUNC102-exact-C3-RET-native-stack-read-live-FEX.log"
PLAN = "original-libc-IFUNC102-exact-C3-RET-hardware-stack-read-source-plan.json"
GDB = "original-libc-IFUNC102-exact-C3-RET-and-writer-one-FEX-guest.gdb"
CERT = "original-libc-IFUNC102-same-guest-call-JIT-return-site-write-real-FEX-verified.json"
OUT = "original-libc-IFUNC102-exact-C3-RET-real-FEX-native-READ-independent-verified.json"


def unique(pattern, text):
    hits = re.findall(pattern, text, re.M)
    assert len(hits) == 1, ("missing, repeated or malformed authentic native event", pattern, len(hits))
    return hits[0]


def ordered(text, markers):
    positions = []
    for marker in markers:
        assert text.count(marker) == 1, ("missing/duplicated stage", marker)
        positions.append(text.index(marker))
    assert positions == sorted(positions) and len(set(positions)) == len(positions), "out-of-order native hardware chain"


def attest(root: Path, raw_override=None):
    libc = (root/"original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6").read_bytes()
    ldso = (root/"original-source-pinned-root/lib64/ld-linux-x86-64.so.2").read_bytes()
    assert len(libc) == 2118168 and hashlib.sha256(libc).hexdigest() == LIBC_SHA
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LDSO_SHA
    assert libc[0xb4f24:0xb4f28] == bytes.fromhex("4889d0c3")
    assert ldso[0xfd5a:0xfd5c] == bytes.fromhex("ffd0")
    assert ldso[0xfd60:0xfd63] == bytes.fromhex("498906")
    plan = json.loads((root/PLAN).read_text())
    assert plan["original_source_libc_sha256"] == LIBC_SHA
    assert plan["original_source_gnu_ldso_sha256"] == LDSO_SHA
    assert plan["exact_original_source_guest_RET_RIP"] == hex(RET)
    assert plan["exact_original_guest_RET_x86_opcode"] == "c3"
    assert plan["original_source_guest_return_stack_slot"] == hex(SLOT)
    assert plan["original_source_guest_return_stack_qword"] == hex(RETURN)
    assert plan["native_guest_hardware_read_of_RET_stack_slot_real_executed"] is False
    assert plan["all_147_original_libc_relocations_closed"] is False
    cert = json.loads((root/CERT).read_text())
    assert cert["one_real_FEX_guest_process_CALL_to_IFUNC_resolver_JIT_and_return_site_target_store_proven"] is True
    assert cert["source_guest_IFUNC_index"] == 102
    assert cert["source_target_after_native_FEX_hardware_store"] == hex(NEW)
    assert cert["explicit_original_guest_IFUNC_RET_opcode_hardware_traced"] is False
    script = (root/GDB).read_text()
    assert script.count("rwatch -location *(unsigned long long *)0x80300f9b8") == 1
    assert "condition 4 $pc" not in script
    assert script.count("watch -location *(unsigned long long *)0x804202d78") == 1
    assert (root/LOG.replace(".log", ".exit")).read_text().strip() == "0"
    text = (root/LOG).read_text(errors="replace") if raw_override is None else raw_override
    assert "Error in sourced command file" not in text
    assert "No registers." not in text
    markers = [
        "KERNIX_G0_LIBC_IFUNC102_EXACT_SOURCE_GNU_CALL_STACK_NATIVE_HW_HIT ",
        "KERNIX_G0_LIBC_IFUNC102_ORIGINAL_GNU_RESOLVER_JIT_ENTRY_NATIVE_HW_PROVEN ",
        "KERNIX_G0_IFUNC102_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP ",
        "KERNIX_G0_IFUNC102_SOURCE_C3_RET_JIT_BOUNDED_TERMINAL ",
        "KERNIX_G0_IFUNC102_EXACT_C3_RET_GUEST_QWORD_HW_READ_ARMED ",
        "KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ ",
        "KERNIX_G0_IFUNC102_EXACT_C3_RET_NATIVE_HW_READ_GUEST_JIT ",
        "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_CALLER_NATIVE_JIT_HEADER ",
        "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_SOURCE_TARGET_OLD_QWORD ",
        "KERNIX_G0_IFUNC102_AFTER_EXACT_C3_RET_NATIVE_WRITE_WATCH_ARMED ",
        "KERNIX_G0_IFUNC102_SAME_PROCESS_AFTER_RET_NATIVE_IFUNC_STORE_STOP ",
        "KERNIX_G0_IFUNC102_AFTER_EXACT_RET_GNU_SOURCE_WRITER_NATIVE_JIT ",
        "KERNIX_G0_IFUNC102_EXACT_C3_RET_HW_READ_AND_NATIVE_WRITER_CHAIN_DIAGNOSTIC_FINISHED_NOT_YET_VERIFIED=1",
    ]
    ordered(text, markers)
    assert text.count("Hardware read watchpoint 4: -location *(unsigned long long *)0x80300f9b8") >= 2
    assert text.count("Hardware watchpoint 5: -location *(unsigned long long *)0x804202d78") >= 2
    a = unique(
        r"^KERNIX_G0_IFUNC102_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=(0x[0-9a-f]+) "
        r"size=(0x[0-9a-f]+) native_pc=(0x[0-9a-f]+) guest_rsp=(0x[0-9a-f]+) "
        r"guest_rax=(0x[0-9a-f]+) native_state=(0x[0-9a-f]+) not_executed_until_stack_read=1$", text)
    assert tuple(int(s,16) for s in a[:2]) == (RET, 1)
    assert int(a[2],16) >= 0xffff00000000
    assert (int(a[3],16),int(a[4],16)) == (SLOT, NEW)
    assert re.search(r"^0x8040b4f27:\s+0xc3\s*$",text,re.M)
    assert re.search(r"^0x80300f9b8:\s+0x000000080100fd5c\s*$",text,re.M)
    b = unique(
        r"^KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ pc=(0x[0-9a-f]+) "
        r"guest_rsp_x8=(0x[0-9a-f]+) returned_rax_x4=(0x[0-9a-f]+) "
        r"native_state_x28=(0x[0-9a-f]+)$", text)
    pc,rsp,rax,state = (int(s,16) for s in b)
    assert pc >= 0xffff00000000 and pc % 4 == 0
    assert rsp in (SLOT, SLOT+8) and rax == NEW and state == int(a[5],16)
    c = unique(
        r"^KERNIX_G0_IFUNC102_EXACT_C3_RET_NATIVE_HW_READ_GUEST_JIT entry=(0x[0-9a-f]+) "
        r"length=(0x[0-9a-f]+) pc=(0x[0-9a-f]+)$",text)
    assert tuple(int(s,16) for s in c) == (RET,1,pc)
    d = unique(
        r"^KERNIX_G0_IFUNC102_AFTER_EXACT_RET_CALLER_NATIVE_JIT_HEADER caller_guest_entry=(0x[0-9a-f]+) "
        r"guest_rsp=(0x[0-9a-f]+) guest_rax=(0x[0-9a-f]+) guest_r14=(0x[0-9a-f]+) "
        r"native_pc=(0x[0-9a-f]+)$", text)
    assert tuple(int(s,16) for s in d[:4]) == (RETURN,SLOT+8,NEW,TARGET)
    assert int(d[4],16) >= 0xffff00000000
    assert re.search(r"^0x804202d78:\s+0x00000000000283d0\s*$",text,re.M)
    assert re.search(r"^0x804202d78:\s+0x00000008040c74a0\s*$",text,re.M)
    e = unique(
        r"^KERNIX_G0_IFUNC102_AFTER_EXACT_RET_GNU_SOURCE_WRITER_NATIVE_JIT entry=(0x[0-9a-f]+) "
        r"size=(0x[0-9a-f]+) count=(\d+) pc=(0x[0-9a-f]+)$",text)
    assert (int(e[0],16),int(e[1],16)) == (STORE,3)
    assert 0 < int(e[2]) <= 16 and int(e[3],16) >= 0xffff00000000
    assert re.search(r"^\s*0x[0-9a-f]+:\s+stlr\s+x4,\s*\[x19\]\s*$",text,re.M)
    assert re.search(r"^0x80100fd60:\s+0x49\s+0x89\s+0x06",text,re.M)
    return {
        "schema":"kernix.g0.original-libc-ifunc102-exact-c3-ret-one-guest-native-hw-read-and-writer.v1",
        "source_original_libc_sha256": LIBC_SHA,
        "source_original_ldso_sha256": LDSO_SHA,
        "one_new_real_linux_ARM64_FEX_guest_observed_source_CALL_resolver_JIT_RET_guest_stack_READ_caller_and_writer": True,
        "original_guest_RET_opcode_c3_and_JIT_source_RIP": hex(RET),
        "original_guest_RET_return_qword_slot":hex(SLOT),
        "native_hardware_read_after_ARM64_PC":hex(pc),
        "native_guest_rsp_at_read":hex(rsp),
        "original_guest_return_address":hex(RETURN),
        "original_ifunc102_result_pointer":hex(NEW),
        "source_target_relocation":hex(TARGET),
        "original_46_IFUNC_complete":False,
        "all_147_libc_RELA_JMPREL_writers_proven":False,
        "same_process_complete_147_relocations_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }


def negatives(root:Path):
    raw=(root/LOG).read_text(errors="replace")
    controls = [
        ("guest_RET_source_forged",r"(^KERNIX_G0_IFUNC102_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP guest_ret=)0x8040b4f27",r"\g<1>0x1"),
        ("read_native_PC_forged",r"(^KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ pc=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("read_GPR_RSP_forged",r"(^KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ [^\n]+ guest_rsp_x8=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("read_rax_forged",r"(^KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ [^\n]+ returned_rax_x4=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("read_hw_marker_removed",r"^Hardware read watchpoint 4: -location \*\(unsigned long long \*\)0x80300f9b8$", "MISSING_HW_READ"),
        ("read_JIT_guest_RIP_forged",r"(^KERNIX_G0_IFUNC102_EXACT_C3_RET_NATIVE_HW_READ_GUEST_JIT entry=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("caller_return_address_forged",r"(^KERNIX_G0_IFUNC102_AFTER_EXACT_RET_CALLER_NATIVE_JIT_HEADER caller_guest_entry=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("write_native_JIT_guest_forged",r"(^KERNIX_G0_IFUNC102_AFTER_EXACT_RET_GNU_SOURCE_WRITER_NATIVE_JIT entry=)0x[0-9a-f]+",r"\g<1>0x1"),
        ("native_store_opcode_missing",r"^\s*0x[0-9a-f]+:\s+stlr\s+x4,\s*\[x19\]\s*$","0x0: ldr x4, [x19]"),
        ("actual_read_event_removed",r"^KERNIX_G0_IFUNC102_EXACT_RET_GUEST_QWORD_REAL_NATIVE_HW_READ [^\n]+$","MISSING_READ_EVENT"),
    ]
    names=[]
    for name,pattern,repl in controls:
        mutant,count=re.subn(pattern,repl,raw,count=0,flags=re.M)
        assert count>=1 and mutant != raw,(name,count)
        try:
            attest(root,raw_override=mutant)
        except AssertionError:
            names.append(name)
        else:
            raise AssertionError("FAIL_OPEN: corrupted authentic native evidence accepted: "+name)
    assert len(names)==10
    return names


def main(root: Path):
    receipt=attest(root)
    names=negatives(root)
    receipt["ten_genuine_native_hardware_log_corruptions_rejected"]=True
    receipt["negative_names"]=names
    (root/OUT).write_text(json.dumps(receipt,indent=2)+"\n")
    print("KERNIX_G0_ORIGINAL_LIBC_IFUNC102_ONE_REAL_FEX_ARM64_GUEST_EXACT_C3_RET_STACK_HW_READ_TO_GNU_WRITER_INDEPENDENT_PASS")


if __name__ == "__main__":
    assert len(sys.argv)==2
    main(Path(sys.argv[1]))
