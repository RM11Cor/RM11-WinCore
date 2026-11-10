#!/usr/bin/env bash
# Original GNU IFUNC125..128: four separate genuine FEX guest hardware watches
# sharing ONE pinned FEX build job, NOT one x86 guest process.
# Raw traces only: no new independently certified writer targets here.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import hashlib,json
from pathlib import Path
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
source=Path('inputs/ifunc125-128-source-certified')
agg=json.loads((source/'original-libc-IFUNC125-128-source-batch-NOT-NATIVE-HARDWARE-PROOF.json').read_text())
assert agg['exact_original_source_indices']==[125,126,127,128]
assert agg['source_candidates_derived_in_one_hash_verified_batch']==4
assert agg['certified_prior_native_writer_ledger']==39
assert agg['new_independently_native_writer_attested_targets']==0
assert agg['full_original_147_same_guest_relocations_proven'] is False
prior=Path('inputs/ifunc124-full-certified/original-libc-IFUNC124-original-one-FEX-CALL-C3-RET-native-stack-read-GNU-writer-INDEPENDENT-PROOF.json')
assert prior.is_file() and not prior.is_symlink()
proof=json.loads(prior.read_text())
assert proof['original_source_IFUNC_index']==124
assert proof['source_original_libc_sha256']==LIBC_SHA
assert proof['source_original_ldso_sha256']==LDSO_SHA
assert proof['genuine_original_linux_FEX_ARM64_ONE_process_IFUNC124_CALL_resolver_JIT_C3_RET_native_hardware_read_and_writer_proven'] is True
assert proof['native_source_original_IFUNC124_distinct_writer_ledger_count']==39
assert proof['ten_genuine_native_hardware_log_corruptions_independently_rejected'] is True
assert proof['all_147_original_libc_RELA_JMPREL_writers_one_process_proven'] is False
assert proof['Android_Bionic_Wine_Proton_games_proven'] is False
seen=set()
for index in range(125,129):
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
    assert obj['previous_unique_native_writers_independently_certified']==39
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
assert len(seen)==4
print('KERNIX_G0_FOUR_RAW_FEX_WRITER_SOURCE_ELF_SHA_AND_PRIOR39_CERTIFIED_READY_NO_NEW_PROOF')
PY

CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
test -s "$PWD/dist/original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"

for index in 125 126 127 128; do
  tag="dist/original-libc-IFUNC$index-four-batch-REAL-FEX-native-WRITE-only"
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
echo KERNIX_G0_FOUR_RAW_IFUNC125_128_FEX_ARM64_WRITER_HITS_NEED_INDEPENDENT_REPLAY_KEEP_LEDGER_39_147
