#!/usr/bin/env bash
# Source-locked original GNU IFUNC121 native ARM64 FEX CALL/C3 RET/stack HW read/GNU writer runtime.
# This emits raw native evidence, not an independent proof or a new writer count.
set -euo pipefail
python3 -m py_compile native-engine/tools/kernix_g0_original_ifunc121_one_guest_dynamic_ret_hardware_plan.py
python3 - <<'PY'
import json
from pathlib import Path
root=Path('dist')
source=Path('inputs/ifunc121-source-RET-certified')
expected=(
  'original-libc-IFUNC121-true-source-x86-C3-RET-candidates-NOT-RUNTIME.json',
  'original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-source-plan.json',
  'original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-and-GNU-writer.gdb'
)
for name in expected:
  p=source/name
  assert p.is_file() and not p.is_symlink(),name
  assert 200<p.stat().st_size<100000,name
  (root/name).write_bytes(p.read_bytes())
prior=Path('inputs/ifunc121-unique-writer-certified/original-libc-IFUNC121-source-locked-distinct-real-FEX-ARM64-native-HW-WRITE-INDEPENDENT-PROOF.json')
assert prior.is_file() and not prior.is_symlink()
proof=json.loads(prior.read_text())
assert proof['original_source_ifunc_index']==121
assert proof['source_original_resolver_guest_RIP']=='0x8040b23c0'
assert proof['original_source_target']=='0x804202c90'
assert proof['new_source_resolver_result_original_libc_RX'] is True
assert int(proof['native_hardware_new_source_target_qword'],16)>0x804000000
assert proof['new_unique_original_ifunc121_native_hardware_writer_independently_proven'] is True
assert proof['unique_original_libc_native_hardware_writer_target_count']==36
assert proof['ten_original_native_hardware_log_corruptions_rejected'] is True
assert proof['original_IFUNC121_resolver_CALL_C3_RET_native_stack_HW_READ_proven'] is False
(root/prior.name).write_bytes(prior.read_bytes())
source_ret=json.loads((root/expected[0]).read_text())
actual=source_ret['source_disassembled_RET_candidates']
assert source_ret['original_IFUNC_source_index']==121 and len(actual)==1
assert actual[0]['guest_source_RIP']=='0x8040b2402'
assert source_ret['previous_unique_native_hardware_writer_ledger']==36
print('KERNIX_G0_IFUNC121_SOURCE_1_RET_AND_AUTHENTIC_PRIOR36_WRITERS_READY_NO_NEW_CHAIN_CLAIM')
PY
python3 native-engine/tools/kernix_g0_original_ifunc121_one_guest_dynamic_ret_hardware_plan.py dist .
python3 - <<'PY'
from pathlib import Path
import json
source=Path('inputs/ifunc121-source-RET-certified')
for name in (
   'original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-source-plan.json',
   'original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-and-GNU-writer.gdb'):
  original=source/name
  generated=Path('dist')/name
  assert original.read_bytes()==generated.read_bytes(),('source GDB plan changed before FEX runtime',name)
p=json.loads(Path('dist/original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-source-plan.json').read_text())
assert p['original_ifunc_index']==121
assert p['original_resolver_guest_RIP']=='0x8040b23c0'
assert p['original_IFUNC121_target']=='0x804202c90'
assert p['original_IFUNC121_source_old_qword']=='0x28200'
proof=json.loads(Path('dist/original-libc-IFUNC121-source-locked-distinct-real-FEX-ARM64-native-HW-WRITE-INDEPENDENT-PROOF.json').read_text())
assert p['expected_real_original_resolver_result_from_prior_write_only_hardware_proof']==proof['native_hardware_new_source_target_qword']
assert p['previous_unique_native_hardware_writers_independently_certified']==36
assert len(p['original_source_RET_guest_RIP_candidates'])==1
assert p['actual_native_hardware_RET_read_and_same_process_writer_proven'] is False
print('KERNIX_G0_IFUNC121_UNMODIFIED_GDB_SOURCE_PREPARED_FOR_ONE_REAL_FEX_GUEST_HARDWARE_TRIAL')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
set +e
timeout -k 5s 225s gdb -q -nx -batch \
  -x dist/original-libc-IFUNC121-original-one-FEX-CALL-C3-RET-native-HW-read-and-GNU-writer.gdb \
  --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
  "$PWD/dist/original-source-pinned-root" \
  >dist/original-libc-IFUNC121-one-FEX-CALL-one-source-RET-native-stack-HW-READ-and-GNU-WRITE.log 2>&1
rc=$?
set -e
echo "$rc" >dist/original-libc-IFUNC121-one-FEX-CALL-one-source-RET-native-stack-HW-READ-and-GNU-WRITE.exit
tail -n 175 dist/original-libc-IFUNC121-one-FEX-CALL-one-source-RET-native-stack-HW-READ-and-GNU-WRITE.log
test "$rc" -eq 0
for marker in \
  'KERNIX_G0_IFUNC121_ORIGINAL_CALL_NATIVE_STACK_HW_HIT ' \
  'KERNIX_G0_IFUNC121_ORIGINAL_RESOLVER_JIT_ENTRY_NATIVE_HW_STOP ' \
  'KERNIX_G0_IFUNC121_ORIGINAL_C3_RET_JIT_NATIVE_HW_STOP ' \
  'KERNIX_G0_IFUNC121_REAL_C3_RET_NATIVE_HARDWARE_READ ' \
  'KERNIX_G0_IFUNC121_ORIGINAL_CALLER_RESUMED_AFTER_C3_RET ' \
  'KERNIX_G0_IFUNC121_SAME_PROCESS_POST_RET_NATIVE_WRITER_HW_HIT '; do
  grep -Fq "$marker" dist/original-libc-IFUNC121-one-FEX-CALL-one-source-RET-native-stack-HW-READ-and-GNU-WRITE.log
done
echo KERNIX_G0_IFUNC121_REAL_FEX_ONE_PROCESS_CALL_C3_RET_STACK_READ_GNU_WRITER_RAW_PASS_NEEDS_INDEPENDENT_REPLAY
