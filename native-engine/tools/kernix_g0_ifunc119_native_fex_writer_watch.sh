#!/usr/bin/env bash
# Preserve genuine original IFUNC119 ARM64 native GDB writer evidence (no new certification by this script).
set -euo pipefail
python3 -m py_compile native-engine/tools/kernix_g0_original_libc_ifunc119_source_distinct_hw_watch_plan.py
python3 - <<'PY'
import json
from pathlib import Path
f='original-libc-IFUNC118-original-one-FEX-CALL-C3-RET-native-stack-read-GNU-writer-INDEPENDENT-PROOF.json'
prior=Path('inputs/ifunc118-full-certified')/f
assert prior.is_file() and not prior.is_symlink()
proof=json.loads(prior.read_text())
assert proof['original_source_IFUNC_index']==118
assert proof['source_original_resolver_guest_RIP']=='0x8040b2360'
assert proof['source_original_RET_guest_RIP'] in proof['source_original_RET_guest_RIP_candidates']
assert proof['source_original_target']=='0x804202cb0'
assert proof['genuine_original_linux_FEX_ARM64_ONE_process_IFUNC118_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven'] is True
assert proof['ten_genuine_native_hardware_log_corruptions_independently_rejected'] is True
assert proof['native_source_original_IFUNC118_distinct_writer_ledger_count']==33
assert proof['new_unique_relocation_count_due_to_RET_proof']==0
assert proof['all_147_original_libc_RELA_JMPREL_writers_one_process_proven'] is False
Path('dist',f).write_bytes(prior.read_bytes())
print('KERNIX_G0_IFUNC119_PRIOR117_FULL_CALL_RET_CERTIFIED_33_WRITERS')
PY
python3 native-engine/tools/kernix_g0_original_libc_ifunc119_source_distinct_hw_watch_plan.py dist . 119
python3 - <<'PY'
import json
from pathlib import Path
source=Path('inputs/ifunc119-original-x86-source')
for name in ('original-libc-IFUNC119-source-only-distinct-native-write-plan.json',
             'original-libc-IFUNC119-source-only-distinct-native-write-plan.gdb'):
  original=source/name
  generated=Path('dist')/name
  assert original.is_file() and not original.is_symlink()
  assert original.read_bytes()==generated.read_bytes(),('original GNU x86 source GDB plan changed',name)
p=json.loads(Path('dist/original-libc-IFUNC119-source-only-distinct-native-write-plan.json').read_text())
assert p['candidate_source_index']==119
assert p['candidate_original_source_table']=='DT_JMPREL'
assert p['candidate_original_table_index']==33
assert p['original_guest_resolver_entry']=='0x8040d8d70'
assert p['original_guest_target']=='0x804202ca0'
assert p['original_target_qword']=='0x28220'
assert p['original_guest_resolver_source_alias_indices']==[119,138]
assert p['verified_previous_unique_native_writer_ledger']==33
assert p['new_candidate_hardware_writer_genuine_observed'] is False
print('KERNIX_G0_IFUNC119_SOURCE_GDB_SHA_BYTE_IDENTICAL_33_PRIOR_NO_NEW_NATIVE_PROOF')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
set +e
timeout -k 5s 135s gdb -q -nx -batch \
  -x dist/original-libc-IFUNC119-source-only-distinct-native-write-plan.gdb \
  --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
  "$PWD/dist/original-source-pinned-root" \
  >dist/original-libc-IFUNC119-real-FEX-native-HW-WRITE-only.log 2>&1
rc=$?
set -e
echo "$rc" >dist/original-libc-IFUNC119-real-FEX-native-HW-WRITE-only.exit
tail -n 105 dist/original-libc-IFUNC119-real-FEX-native-HW-WRITE-only.log
test "$rc" -eq 0
for marker in \
  'KERNIX_G0_GENERIC_IFUNC119_ORIGINAL_NATIVE_SOURCE_WRITE_WATCH_ARMED ' \
  'KERNIX_G0_GENERIC_IFUNC119_NATIVE_HW_TARGET_WRITER_OBSERVED ' \
  'KERNIX_G0_GENERIC_IFUNC119_NATIVE_SOURCE_WRITER_JIT '; do
  grep -Fq "$marker" dist/original-libc-IFUNC119-real-FEX-native-HW-WRITE-only.log
done
echo KERNIX_G0_IFUNC119_REAL_ARM64_FEX_NATIVE_HW_WRITER_RAW_OBSERVED_NEEDS_INDEPENDENT_ATTESTATION
