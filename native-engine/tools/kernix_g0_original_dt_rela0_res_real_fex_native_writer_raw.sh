#!/usr/bin/env bash
# R_X86_64_64 first original GNU DT_RELA index 0 _res BSS symbol.
# One FEX Linux ARM64 GDB hardware write watch. RAW diagnostics only.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'native-engine/tools')
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
root=Path('dist/original-source-pinned-root')
libc=(root/'lib/x86_64-linux-gnu/libc.so.6').read_bytes()
ldso=(root/'lib64/ld-linux-x86-64.so.2').read_bytes()
assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
r=decode_original_libc(libc)[0]
assert (r['index'],r['table'],r['table_index'],r['r_type'],r['r_sym'],r['r_offset'],r['r_addend'])==(0,'DT_RELA',0,1,2726,'0x1ffc68',0)
assert r['source_guest_target']=='0x8041ffc68' and r['original_source_qword']=='0x0'
offset=source_offset(libc,0x1ffc68,8,6,nonexec=True)
assert int.from_bytes(libc[offset:offset+8],'little')==0
p='original-libc-DT-RELA0-R_X86_64_64-_res-source-only-NO-NATIVE-WRITER-PROOF'
base=Path('inputs/dt-rela0-res-source')
plan=base/(p+'.json'); script=base/(p+'.gdb')
assert plan.is_file() and script.is_file() and not plan.is_symlink() and not script.is_symlink()
j=json.loads(plan.read_text())
assert j['original_source_libc_sha256']==LIBC_SHA
assert j['original_source_ldso_sha256']==LDSO_SHA
assert j['original_relocation_index']==0 and j['original_table']=='DT_RELA'
assert j['relocation_type']=='R_X86_64_64' and j['original_symbol_index']==2726
assert j['original_symbol_name']=='_res' and j['original_symbol_source_in_bss'] is True
assert j['original_guest_target']=='0x8041ffc68'
assert j['original_source_target_qword']=='0x0'
assert j['symbol_local_definition_candidate_guest_address']=='0x80420b680'
assert j['symbol_preemption_or_versioned_runtime_lookup_proven'] is False
assert j['previous_native_writer_targets_independently_certified']==62
assert j['new_native_writer_targets_in_this_source_only_stage']==0
g=script.read_text()
assert g.startswith('set pagination off\nset confirm off\n')
assert g.count('watch -location *(unsigned long long *)0x8041ffc68')==1
assert 'KERNIX_G0_RELA0_RES_SOURCE_ONLY_WATCH_ARM' in g
assert 'KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH' in g
ledger=Path('inputs/previous62-ledger/original-libc-147-source-batch-native-proof-ledger62-NO-NEW-HW-RUN.json')
assert ledger.is_file() and not ledger.is_symlink()
prior=json.loads(ledger.read_text())
assert prior['source_original_libc_sha256']==LIBC_SHA
assert prior['source_original_ldso_sha256']==LDSO_SHA
assert prior['previously_independently_attested_native_writer_target_count']==62
assert prior['remaining_requires_separate_native_hardware_evidence']==85
assert 0 in prior['remaining_non_IFUNC_DT_RELA_indices']
assert 0 not in prior['previously_attested_original_source_indices']
assert prior['native_IFUNC85_DT_RELA_real_zero_to_zero_FEX_JIT_hardware_STORE_independently_proven'] is True
Path('dist',plan.name).write_bytes(plan.read_bytes())
Path('dist',script.name).write_bytes(script.read_bytes())
print('KERNIX_G0_SOURCE_GNU_DT_RELA0_R_X86_64_64_RES_BSS_GUEST_WATCH_PRIOR62_READY_RAW_ONLY')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
tag="dist/original-libc-DT-RELA0-R_X86_64_64-_res-REAL-ARM64-FEX-RAW-NATIVE-WRITER"
gdbfile="dist/original-libc-DT-RELA0-R_X86_64_64-_res-source-only-NO-NATIVE-WRITER-PROOF.gdb"
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
import hashlib,json,re
from pathlib import Path
prefix='original-libc-DT-RELA0-R_X86_64_64-_res-REAL-ARM64-FEX-RAW-NATIVE-WRITER'
root=Path('dist')
log=(root/(prefix+'.log')).read_text(errors='replace')
rc=int((root/(prefix+'.exit')).read_text().strip())
target='0x8041ffc68'
arm=log.find('KERNIX_G0_RELA0_RES_SOURCE_ONLY_WATCH_ARM target='+target)
hit=log.find('KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH target='+target)
count=len(re.findall(r'^Hardware watchpoint 2: -location \*\(unsigned long long \*\)'+target+'$',log,re.M))
data={
 'schema':'kernix.g0.original-dt-rela0-R_X86_64_64-res-real-arm64-fex-raw-writer.v1',
 'original_relocation_index':0,
 'original_table':'DT_RELA',
 'original_relocation_type':'R_X86_64_64',
 'original_symbol':'_res',
 'original_symbol_definition_in_bss':True,
 'original_target_initial_qword':'0x0',
 'original_guest_target':target,
 'source_defined_symbol_address_candidate':'0x80420b680',
 'symbol_interposition_lookup_native_semantics_proven':False,
 'native_real_arm64_watch_armed':arm>=0,
 'native_real_arm64_write_hit_candidate':hit>arm>=0 and count==2,
 'gdb_exit_code':rc,
 'raw_native_log_sha256':hashlib.sha256(log.encode()).hexdigest(),
 'native_hardware_write_independently_attested':False,
 'prior_native_writer_count':62,
 'new_native_writer_proofs_from_this_raw_diagnostic':0,
 'all_147_same_guest_native_execution_proven':False,
 'Android_Bionic_Wine_Proton_games_proven':False,
}
assert len(log)>100
(root/(prefix+'.json')).write_text(json.dumps(data,indent=2)+'\n')
print('KERNIX_G0_FIRST_NON_IFUNC_ORIGINAL_GNU_REAL_ARM64_FEX_RAW_DIAGNOSTIC_NO_PROOF',json.dumps(data,sort_keys=True))
PY
tail -n 80 "$tag.log"
echo KERNIX_G0_ORIGINAL_GNU_DT_RELA0_R_X86_64_64_RES_FEX_RAW_ONLY_KEEP_62_147
