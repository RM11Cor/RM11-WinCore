#!/usr/bin/env bash
# Original GNU IFUNC145..146: two separate genuine FEX guest hardware watches
# sharing ONE pinned FEX build job, NOT one x86 guest process.
# Raw traces only: no new independently certified writer targets here.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0, 'native-engine/tools')
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset

root=Path('dist/original-source-pinned-root')
libp=root/'lib/x86_64-linux-gnu/libc.so.6'
ldp=root/'lib64/ld-linux-x86-64.so.2'
assert libp.is_file() and ldp.is_file() and not libp.is_symlink() and not ldp.is_symlink()
libc,ldso=libp.read_bytes(),ldp.read_bytes()
assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
rows=decode_original_libc(libc)
source=Path('inputs/ifunc145-146-source-certified')
agg=json.loads((source/'original-libc-IFUNC145-146-source-batch-NOT-NATIVE-HARDWARE-PROOF.json').read_text())
assert agg['exact_original_source_indices']==[145,146]
assert agg['source_candidates_derived_in_one_hash_verified_batch']==2
assert agg['certified_prior_native_writer_ledger']==59
assert agg['new_independently_native_writer_attested_targets']==0
assert agg['full_original_147_same_guest_relocations_proven'] is False
prior=Path('inputs/ifunc141-144-prior-writers/original-libc-IFUNC141-144-four-independent-native-hardware-writer-batch-PROOF.json')
assert prior.is_file() and not prior.is_symlink()
proof=json.loads(prior.read_text())
assert proof['original_source_libc_sha256']==LIBC_SHA
assert proof['original_source_ldso_sha256']==LDSO_SHA
assert proof['original_source_indices']==[141,142,143,144]
assert proof['prior_independently_certified_native_hardware_target_count']==55
assert proof['new_distinct_original_GNU_native_hardware_writer_targets']==4
assert proof['unique_original_libc_native_hardware_writer_target_count']==59
assert len(proof['four_independent_native_hardware_writer_receipts'])==4
assert all(x['native_source_hardware_write_independently_attested'] is True for x in proof['four_independent_native_hardware_writer_receipts'])
assert sum(len(v) for v in proof['forty_native_hardware_tamper_cases_rejected'].values())==40
assert proof['one_single_FEX_guest_process_for_all_four_writes_proven'] is False
assert proof['original_IFUNC141_144_CALL_C3_RET_native_stack_HW_READ_proven'] is False
assert proof['all_147_original_libc_RELA_JMPREL_writers_same_process_proven'] is False
assert proof['Android_Bionic_Wine_Proton_games_proven'] is False
seen=set()
for index in range(145,147):
    stem=f'original-libc-IFUNC{index}-source-only-distinct-native-write-plan'
    jpath=source/(stem+'.json')
    gpath=source/(stem+'.gdb')
    assert jpath.is_file() and gpath.is_file() and not jpath.is_symlink() and not gpath.is_symlink()
    obj=json.loads(jpath.read_text())
    row=rows[index]
    target=0x804000000+int(row['r_offset'],16)
    resolver=0x804000000+row['r_addend']
    old=int(row['original_source_qword'],16)
    assert row['r_type']==37 and row['r_sym']==0 and row['table']=='DT_JMPREL'
    assert row['table_index']==index-86
    assert obj['original_relocation_index']==index
    assert obj['original_table_ordinal']==index-86
    assert obj['original_guest_resolver']==hex(resolver)
    assert obj['original_guest_target']==hex(target)
    assert obj['original_unmodified_target_qword']==hex(old)
    assert obj['source_plan_only_not_real_native_FEX_execution'] is True
    assert obj['this_batch_new_native_writer_receipts']==0
    assert obj['previous_unique_native_writers_independently_certified']==59
    assert obj['original_guest_target'] not in seen
    seen.add(obj['original_guest_target'])
    off=source_offset(libc,int(row['r_offset'],16),8,6,nonexec=True)
    assert int.from_bytes(libc[off:off+8],'little')==old
    gdb=gpath.read_text()
    assert gdb.count(f'watch -location *(unsigned long long *){hex(target)}')==1
    assert 'awatch -location' not in gdb and 'rwatch -location' not in gdb
    assert f'KERNIX_G0_BATCH_IFUNC{index}_SOURCE_ONLY_WATCH_ARMED' in gdb
    assert f'KERNIX_G0_BATCH_IFUNC{index}_RAW_TARGET_HARDWARE_HIT' in gdb
    assert f'KERNIX_G0_BATCH_IFUNC{index}_SOURCE_GNU_JIT' in gdb
    (Path('dist')/(stem+'.gdb')).write_bytes(gpath.read_bytes())
    (Path('dist')/(stem+'.json')).write_bytes(jpath.read_bytes())
assert len(seen)==2
print('KERNIX_G0_TWO_RAW_FEX_WRITER_SOURCE_ELF_SHA_AND_PRIOR59_CERTIFIED_READY_NO_NEW_PROOF')
PY

CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
test -s "$PWD/dist/original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"

for index in 145 146; do
  tag="dist/original-libc-IFUNC$index-two-batch-REAL-FEX-native-WRITE-only"
  src="dist/original-libc-IFUNC$index-source-only-distinct-native-write-plan.gdb"
  test -s "$src"
  set +e
  timeout -k 5s 180s gdb -q -nx -batch \
    -x "$src" \
    --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
    "$PWD/dist/original-source-pinned-root" \
    >"$tag.log" 2>&1
  rc=$?
  set -e
  echo "$rc" >"$tag.exit"
  tail -n 65 "$tag.log"
  test "$rc" -eq 0
  grep -Fq "KERNIX_G0_BATCH_IFUNC${index}_SOURCE_ONLY_WATCH_ARMED " "$tag.log"
  grep -Fq "KERNIX_G0_BATCH_IFUNC${index}_RAW_TARGET_HARDWARE_HIT " "$tag.log"
  grep -Fq "KERNIX_G0_BATCH_IFUNC${index}_SOURCE_GNU_JIT " "$tag.log"
  grep -Fq "KERNIX_G0_BATCH_IFUNC${index}_RAW_WRITER_ONLY_NO_ATTESTATION=1" "$tag.log"
  grep -Fq 'stlr' "$tag.log"
  echo "KERNIX_G0_BATCH_IFUNC${index}_REAL_FEX_ARM64_RAW_WATCH_OBSERVED_NOT_INDEPENDENTLY_ATTESTED"
done
echo KERNIX_G0_TWO_RAW_IFUNC145_146_FEX_ARM64_WRITER_HITS_NEED_INDEPENDENT_REPLAY_KEEP_LEDGER_59_147
