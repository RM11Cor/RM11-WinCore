#!/usr/bin/env bash
# Strict original GNU IFUNC85 DT_RELA ZERO-source target diagnostic, not attestation.
# The target may be written on an earlier loader path than JMPREL; never assume.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'native-engine/tools')
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
root=Path('dist/original-source-pinned-root')
libcpath=root/'lib/x86_64-linux-gnu/libc.so.6'
ldsopath=root/'lib64/ld-linux-x86-64.so.2'
assert libcpath.is_file() and ldsopath.is_file()
libc,ldso=libcpath.read_bytes(),ldsopath.read_bytes()
assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
rows=decode_original_libc(libc)
row=rows[85]
assert (row['index'],row['table'],row['table_index'],row['r_type'],row['r_sym'])==(85,'DT_RELA',85,37,0)
assert row['original_source_qword']=='0x0'
target=int(row['source_guest_target'],16)
assert target==0x804000000+int(row['r_offset'],16)
off=source_offset(libc,int(row['r_offset'],16),8,6,nonexec=True)
assert int.from_bytes(libc[off:off+8],'little')==0
source=Path('inputs/ifunc85-dt-rela-source-only')
prefix='original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF'
planpath=source/(prefix+'.json')
gdbpath=source/(prefix+'.gdb')
assert planpath.is_file() and gdbpath.is_file()
assert not planpath.is_symlink() and not gdbpath.is_symlink()
plan=json.loads(planpath.read_text())
assert plan['original_relocation_index']==85 and plan['original_table']=='DT_RELA'
assert plan['original_source_libc_sha256']==LIBC_SHA
assert plan['original_source_ldso_sha256']==LDSO_SHA
assert plan['original_guest_target']==hex(target)
assert plan['original_unmodified_target_qword']=='0x0'
assert plan['new_native_writer_attestations']==0
assert plan['previously_independently_certified_native_writers']==61
assert plan['prewatch_may_be_after_DT_RELA_write'] is True
prior=Path('inputs/ifunc145-146-prior-certified/original-libc-IFUNC145-146-two-independent-native-hardware-writer-batch-PROOF.json')
assert prior.is_file() and not prior.is_symlink()
proof=json.loads(prior.read_text())
assert proof['original_source_libc_sha256']==LIBC_SHA
assert proof['original_source_ldso_sha256']==LDSO_SHA
assert proof['original_source_indices']==[145,146]
assert proof['prior_independently_certified_native_hardware_target_count']==59
assert proof['unique_original_libc_native_hardware_writer_target_count']==61
assert len(proof['two_independent_native_hardware_writer_receipts'])==2
assert all(x['native_source_hardware_write_independently_attested'] is True for x in proof['two_independent_native_hardware_writer_receipts'])
assert sum(map(len, proof['twenty_native_hardware_tamper_cases_rejected'].values()))==20
assert proof['all_147_original_libc_RELA_JMPREL_writers_same_process_proven'] is False
gdb=gdbpath.read_text()
assert gdb.startswith('set pagination off\nset confirm off\n')
assert len(gdb.splitlines())>=16
assert gdb.count(f'watch -location *(unsigned long long *){hex(target)}')==1
assert f'KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target={hex(target)}' in gdb
assert 'KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT' in gdb
assert 'rwatch -location' not in gdb and 'awatch -location' not in gdb
for src in (planpath,gdbpath):
    (Path('dist')/src.name).write_bytes(src.read_bytes())
print('KERNIX_G0_IFUNC85_REAL_ARM64_FEX_CANDIDATE_SOURCE_SHA_ZERO_QWORD_AND_PRIOR61_VALIDATED')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
test -s "$PWD/dist/original-source-pinned-root/lib/x86_64-linux-gnu/libc.so.6"
tag="dist/original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-DIAGNOSTIC"
gdbfile="dist/original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.gdb"
test -s "$gdbfile"
set +e
timeout -k 5s 180s gdb -q -nx -batch \
  -x "$gdbfile" \
  --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
  "$PWD/dist/original-source-pinned-root" \
  >"$tag.log" 2>&1
rc=$?
set -e
echo "$rc" >"$tag.exit"
python3 - <<'PY'
import json,hashlib,re
from pathlib import Path
prefix='original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-DIAGNOSTIC'
p=Path('dist')/prefix
log=(p.with_suffix('.log')).read_text(errors='replace')
rc=int((p.with_suffix('.exit')).read_text().strip())
plan=json.loads(Path('dist/original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.json').read_text())
target=plan['original_guest_target']
marker='KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target='+target
prefix_hit='KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT target='+target
marker_at=log.find(marker)
hit_at=log.find(prefix_hit)
diagnostic={
    'schema':'kernix.g0.original-ifunc85-dt-rela-zero-real-arm64-fex-raw-diagnostic.v1',
    'original_source_index':85,
    'original_table':'DT_RELA',
    'original_target_qword_before_guest_execution':'0x0',
    'original_source_target':target,
    'gdb_process_exit_code':rc,
    'candidate_arm_marker_seen':marker_at>=0,
    'candidate_after_arm_raw_watch_hit_marker_seen':hit_at>marker_at>=0,
    'candidate_raw_hardware_log_sha256':hashlib.sha256(log.encode()).hexdigest(),
    'candidate_watch_log_length':len(log),
    'native_hardware_write_independently_attested':False,
    'all_147_relocations_same_guest_proven':False,
    'Android_Bionic_Wine_Proton_games_proven':False,
    'raw_hits_need_actual_source_guest_store_independent_provenance':True,
    'old_native_writer_ledger_still_valid_count':61,
}
assert target.startswith('0x804') and len(log)>100
(Path('dist')/(prefix+'.json')).write_text(json.dumps(diagnostic,indent=2)+'\n')
print('KERNIX_G0_IFUNC85_DT_RELA_ARM64_RAW_CANDIDATE_NOT_INDEPENDENT',json.dumps(diagnostic,sort_keys=True))
PY
tail -n 95 "$tag.log"
echo KERNIX_G0_IFUNC85_DT_RELA_ONLY_RAW_HARDWARE_DIAGNOSTIC_KEEP_61_OF_147
