#!/usr/bin/env python3
"""Four NEXT original libc JMPREL write-only hardware watches in ONE real FEX guest.

PREPARE: source-only, checks eleven proven original Linux ARM64 FEX
ELF JMPREL writer receipts, NOT Android/JNI or Windows code.
The GDB Python script arms 4 distinct native WRITE watchpoints together
at the genuine source-loader close(3) break, captures each GDB after-store
native PC, source x86 guest JIT RIP, and original source old/new values.
Neither the GDB script nor an armed hardware watch counts as a new writer.
A separately fail-closed validator must attribute both real native writes.
"""
import hashlib
import json
from pathlib import Path
import sys
from kernix_g0_libc_rela_source_inventory_gate import make_inventory

SOURCE_MAIN = "native-engine/android-host/tests/kernix_g0_original_fex_full_ptload_source_executable_range_arm64.cpp"
LD_SHA = "cff2a563ca82b90beb5c43db38b84efe0c610a9a0e3394083882abcf8431fbae"
PLAN = "original-libc-symbolic-jmprel-97-100-same-native-guest-source-plan.json"
GDB = "original-libc-symbolic-jmprel-97-100-same-native-guest-watch.gdb"
TARGETS = (
    (97, 0x804202d28, 0x28330, 14),
    (98, 0x804202d48, 0x28370, 15),
    (99, 0x804202d58, 0x28390, 16),
    (100, 0x804202d60, 0x283a0, 18),
)


def prepare(dist: Path, repository: Path):
    libcfile = dist / "original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
    ldsofile = dist / "original-source-pinned-root/lib64/ld-linux-x86-64.so.2"
    assert libcfile.is_file() and not libcfile.is_symlink()
    assert ldsofile.is_file() and not ldsofile.is_symlink()
    ldso = ldsofile.read_bytes()
    assert len(ldso) == 235408 and hashlib.sha256(ldso).hexdigest() == LD_SHA
    inventory = make_inventory(libcfile.read_bytes())
    assert inventory == json.loads(
        (dist / "original-libc-147-rela-jmprel-source-inventory.json").read_text())
    source = inventory["next_source_candidates"]
    assert [x["index"] for x in source[:14]] == list(range(87, 101))
    for (idx, target, old, symbol), row in zip(TARGETS, source[10:14]):
        assert (row["index"], row["table"], row["r_type"], row["r_sym"]) == (
            idx, "DT_JMPREL", 7, symbol)
        assert int(row["source_guest_target"], 16) == target
        assert int(row["source_qword"], 16) == old
        assert target == 0x804000000 + int(row["r_offset"], 16)

    # The first five + the previous two same-process REAL native hardware receipts
    # authorize a new four-target batch. These JSON receipts were independently
    # confirmed in source-pinned prior Linux ARM64 FEX evidence replays.
    proofs = [
        ("original-fex-libc-symbolic-jmprel-first-real-native-writer-proof.json",
         "selected_original_record_index", 86,
         "one_original_libc_symbolic_JMPREL_real_hardware_store_proven"),
        ("original-libc-next-symbolic-jmprel-live-fex-hw-verified.json",
         "source_record_index", 87,
         "genuine_second_symbolic_source_hardware_store_proven"),
        ("original-libc-third-symbolic-jmprel-real-fex-hw-verified.json",
         "third_original_source_relocation_index", 88,
         "third_symbolic_JMPREL_real_native_hardware_writer_proven"),
        ("original-libc-fourth-symbolic-jmprel-real-fex-hw-verified.json",
         "fourth_source_index", 89,
         "fourth_symbolic_JMPREL_real_native_hardware_store_proven"),
        ("original-libc-fifth-symbolic-jmprel-real-fex-hw-verified.json",
         "fifth_source_index", 90,
         "fifth_symbolic_JMPREL_real_native_hardware_store_proven"),
    ]
    for name, index_name, index, proven in proofs:
        record = json.loads((dist / name).read_text())
        assert record[index_name] == index and record[proven] is True
    fifth = json.loads((dist / proofs[-1][0]).read_text())
    assert fifth["source_original_libc_sha256"] == inventory["libc_source_sha256"]
    assert fifth["source_original_gnu_ldso_sha256"] == LD_SHA
    assert fifth["fifth_source_guest_target"] == "0x804202c48"
    assert fifth["fifth_original_qword"] == "0x28170"
    assert fifth["fifth_after_native_hardware_store_qword"] == "0x801017830"
    assert fifth["individual_symbolic_JMPREL_hardware_writers_proven"] == 5
    assert fifth["six_actual_native_log_negative_mutations_rejected"] is True
    assert len(fifth["negative_names"]) == 6

    previous_batch = json.loads(
        (dist / "original-libc-symbolic-jmprel-91-92-same-native-guest-verified.json").read_text())
    assert previous_batch["libc_sha256"] == inventory["libc_source_sha256"]
    assert previous_batch["ldso_sha256"] == LD_SHA
    assert previous_batch["two_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert previous_batch["indices"] == [91, 92]
    assert previous_batch["total_individually_real_native_attested_original_libc_JMPREL"] == 7
    assert previous_batch["six_actual_same_process_hw_batch_log_mutations_rejected"] is True
    assert len(previous_batch["negative_case_names"]) == 6
    assert previous_batch["one_process_full_147_relocation_closure_proven"] is False
    assert len(previous_batch["writers"]) == 2
    assert (previous_batch["writers"][0]["original_guest_target"],
            previous_batch["writers"][0]["after_real_hardware_write_qword"]) == (
            "0x804202c70", "0x801001250")
    assert (previous_batch["writers"][1]["original_guest_target"],
            previous_batch["writers"][1]["after_real_hardware_write_qword"]) == (
            "0x804202ca8", "0x8010011f0")

    # Independently replay-attested four-source hardware writer evidence
    # is required in addition to the first 7 source-attested writes.
    completed_four = json.loads(
        (dist / "original-libc-symbolic-jmprel-93-96-same-native-guest-verified.json").read_text())
    assert completed_four["libc_sha256"] == inventory["libc_source_sha256"]
    assert completed_four["ldso_sha256"] == LD_SHA
    assert completed_four["four_individual_real_native_hardware_writes_in_ONE_FEX_guest_proven"] is True
    assert completed_four["indices"] == [93,94,95,96]
    assert completed_four["source_original_writer_indices_prior"] == [86,87,88,89,90,91,92]
    assert completed_four["total_individually_real_native_attested_original_libc_JMPREL"] == 11
    assert completed_four["twelve_actual_same_process_hw_batch_log_mutations_rejected"] is True
    assert len(completed_four["negative_case_names"]) == 12
    assert len(completed_four["writers"]) == 4
    assert [v["original_guest_target"] for v in completed_four["writers"]] == [
        "0x804202cc0", "0x804202ce0", "0x804202d00", "0x804202d18"]
    assert [v["after_real_hardware_write_qword"] for v in completed_four["writers"]] == [
        "0x80101ae60", "0x801015760", "0x80100a0d0", "0x801014580"]
    assert completed_four["one_process_full_147_relocation_closure_proven"] is False

    source_lines = (repository / SOURCE_MAIN).read_text().splitlines()
    matches = [i for i, line in enumerate(source_lines, 1)
               if line.strip() == "++RealOriginalLdsoLibcCloses;"]
    assert len(matches) == 1

    # GDB Python callbacks are true write-only GDB hardware watchpoints, not
    # synthesized events. The first three writes silently continue; the fourth
    # distinct target returns True to stop the guest, preserving ONE process.
    # Each stop independently captures AFTER store, native JIT x13/x4, and
    # exact old source qword. Source ELF provenance is checked offline later.
    gdb_python = r'''import gdb

_targets = __TARGETS__
_hits = {}
_watchers = []  # retain GDB Python breakpoint objects for the entire guest run
_failed = False

class KernixBatchStop(gdb.Breakpoint):
    def __init__(self, rec):
        self.rec = rec
        target = int(rec['target'], 16)
        super().__init__('*(unsigned long long *)0x%x' % target,
                         type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE)
        self.condition = '$pc >= 0xffff00000000 && $x28 >= 0xffff00000000'

    def stop(self):
        global _failed
        r = self.rec
        index = r['index']
        try:
            pc = int(gdb.parse_and_eval('$pc'))
            x4 = int(gdb.parse_and_eval('$x4'))
            x13 = int(gdb.parse_and_eval('$x13'))
            x8 = int(gdb.parse_and_eval('$x8'))
            x28 = int(gdb.parse_and_eval('$x28'))
            target = int(r['target'], 16)
            old = int(r['old'], 16)
            after = int(gdb.parse_and_eval('*(unsigned long long *)0x%x' % target))
            inst = gdb.execute('x/i 0x%x' % (pc-4), to_string=True).strip()
            inst = inst.split(':',1)[-1].strip().replace('\t',' ').replace(' ','_')
            h = int(gdb.parse_and_eval('*(unsigned long long *)0x%x' % x28))
            offset = int(gdb.parse_and_eval('*(unsigned int *)0x%x' % h))
            tail = h+offset
            guest = int(gdb.parse_and_eval('*(unsigned long long *)0x%x' % (tail+8)))
            guest_size = int(gdb.parse_and_eval('*(unsigned long long *)0x%x' % (tail+16)))
            count = int(gdb.parse_and_eval('*(unsigned int *)0x%x' % (tail+24)))
            source = gdb.selected_inferior().read_memory(guest,8).tobytes().hex()
            if index in _hits:
                print('KERNIX_G0_BATCH_DUPLICATE_HW_WATCH_INDEX_%d_FAIL' % index, flush=True)
                _failed = True
                return True
            print('KERNIX_G0_BATCH_REAL_GDB_HW_WRITE '
                  'index=%d target=0x%x original=0x%x after=0x%x '
                  'pc=0x%x x4=0x%x x13=0x%x x8=0x%x x28=0x%x '
                  'guest=0x%x size=0x%x insn_count=%d '
                  'original_guest_bytes8=%s native_store=%s' %
                  (index,target,old,after,pc,x4,x13,x8,x28,guest,guest_size,
                   count,source,inst),flush=True)
            _hits[index] = True
            if len(_hits) == len(_targets):
                print('KERNIX_G0_BATCH_FOUR_DISTINCT_GENUINE_HW_WRITE_STOPS '
                      'observed_indices=97,98,99,100 no_full_libc_closure=1',flush=True)
                return True
            return False
        except Exception as e:
            print('KERNIX_G0_BATCH_GDB_STOP_CAPTURE_ERROR index=%d error=%r' %
                  (index,e),flush=True)
            _failed = True
            return True

def kernix_arm_native_batch():
    """Called from normal GDB CLI breakpoint commands, NOT inside a Python
    Breakpoint.stop callback: GDB prohibits adding watchpoints inside stop().
    """
    global _failed
    try:
        for r in _targets:
            target = int(r['target'],16)
            old = int(r['old'],16)
            observed = int(gdb.parse_and_eval(
                '*(unsigned long long *)0x%x' % target))
            if observed != old:
                raise RuntimeError('source qword not pristine index %s' % r['index'])
        print('KERNIX_G0_BATCH_FOUR_ORIGINAL_SOURCE_QWORDS_PRISTINE '
              'indices=97,98,99,100 boundary=close3 no_writer_yet=1',flush=True)
        for r in _targets:
            _watchers.append(KernixBatchStop(r))
        assert len(_watchers) == 4
        print('KERNIX_G0_BATCH_FOUR_WRITE_ONLY_NATIVE_WATCHES_ARMED '
              'indices=97,98,99,100 no_writer_yet=1',flush=True)
    except Exception as e:
        print('KERNIX_G0_BATCH_WATCH_SETUP_ERROR %r' % e,flush=True)
        _failed = True
        raise

'''
    parameters = {
        "__TARGETS__": repr([{"index": i, "target": hex(t), "old": hex(v)}
                             for i, t, v, _ in TARGETS]),
    }
    for key, value in parameters.items():
        assert key in gdb_python
        gdb_python = gdb_python.replace(key, value)
    assert not any(key in gdb_python for key in parameters)
    code = (
        "set pagination off\nset confirm off\n"
        "set breakpoint pending on\nset output-radix 16\n"
        "handle SIGBUS nostop noprint pass\n"
        "handle SIGCHLD nostop noprint pass\n"
        "python\n" + gdb_python + "end\n"
        # Breakpoint-command Python runs only after original libc close(3)
        # pre-relocation boundary; unlike Breakpoint.stop it may safely
        # create hardware watchpoints. Normal CLI 'continue' resumes guest.
        "break " + SOURCE_MAIN + ":" + str(matches[0]) + "\n"
        "commands\nsilent\npython kernix_arm_native_batch()\ncontinue\nend\n"
        "run\n"
        "python\n"
        "if not _failed and set(_hits) == {97,98,99,100}:\n"
        "    print('KERNIX_G0_BATCH_GDB_FOUR_TARGETS_STOP_COMPLETE_NO_SOURCE_ATTESTATION_YET',flush=True)\n"
        "else:\n"
        "    print('KERNIX_G0_BATCH_GDB_INCOMPLETE_FAIL',flush=True)\n"
        "end\n"
        "quit\n")
    assert code.count("KernixBatchStop(r)") == 1
    assert code.count("wp_class=gdb.WP_WRITE") == 1
    assert "gdb.WP_ACCESS" not in code
    assert "awatch " not in code
    assert "KERNIX_G0_BATCH_GDB_INCOMPLETE_FAIL" in code
    (dist / GDB).write_text(code)
    receipt = {
        "schema": "kernix.g0.four-concurrent-libc-symbolic-jmprel-real-native-hw-source-plan.v2",
        "original_libc_sha256": inventory["libc_source_sha256"],
        "original_ldso_sha256": LD_SHA,
        "prior_eleven_writer_indices_source_attested": list(range(86,97)),
        "new_source_original_symbolic_jmprel_records": [
            {"index": i, "original_guest_target": hex(t),
             "original_source_qword": hex(v), "source_symbol": sym}
            for i, t, v, sym in TARGETS],
        "original_breakpoint_source_file": SOURCE_MAIN,
        "original_breakpoint_line": matches[0],
        "watchpoint_count": 4,
        "hardware_watchpoint_mode": "write-only",
        "same_original_FEX_guest_process_requested": True,
        "actual_native_source_guest_execution_performed": False,
        "all_four_original_hardware_writers_proven": False,
        "original_guest_main_relocations_closed": False,
        "full_glibc_relocations_closed": False,
        "original_IFUNC_46_resolvers_proven": False,
        "Android_Bionic_Wine_Proton_games_proven": False,
    }
    (dist / PLAN).write_text(json.dumps(receipt, indent=2) + "\n")
    print("KERNIX_G0_FOUR_CONCURRENT_SOURCE_PINNED_NATIVE_HW_WATCHES_PREPARED_NOT_RUN")


if __name__ == "__main__":
    assert len(sys.argv) == 3
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
