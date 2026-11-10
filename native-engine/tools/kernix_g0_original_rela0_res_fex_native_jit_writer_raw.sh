#!/usr/bin/env bash
# Original GNU libc DT_RELA ordinal0 R_X86_64_64 _res native JIT source
# and AArch64 STLR x13,[x4] witness, RAW ONLY, no 63/147 claim.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import json,hashlib,sys
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
assert (r['index'],r['table'],r['table_index'],r['r_type'],r['r_sym'],r['r_offset'],r['r_addend'],r['original_source_qword'])==(0,'DT_RELA',0,1,2726,'0x1ffc68',0,'0x0')
assert r['source_guest_target']=='0x8041ffc68'
off=source_offset(libc,0x1ffc68,8,6,nonexec=True)
assert libc[off:off+8]==bytes(8)
src=Path('inputs/dt-rela0-res-source')
prefix='original-libc-DT-RELA0-R_X86_64_64-_res-source-only-NO-NATIVE-WRITER-PROOF'
p=json.loads((src/(prefix+'.json')).read_text())
assert p['original_source_libc_sha256']==LIBC_SHA
assert p['original_source_ldso_sha256']==LDSO_SHA
assert p['original_relocation_index']==0 and p['original_symbol_name']=='_res'
assert p['original_guest_target']=='0x8041ffc68' and p['original_source_target_qword']=='0x0'
assert p['symbol_local_definition_candidate_guest_address']=='0x80420b680'
assert p['previous_native_writer_targets_independently_certified']==62
assert p['new_native_writer_targets_in_this_source_only_stage']==0
assert p['symbol_preemption_or_versioned_runtime_lookup_proven'] is False
prior=json.loads(Path('inputs/previous62-ledger/original-libc-147-source-batch-native-proof-ledger62-NO-NEW-HW-RUN.json').read_text())
assert prior['previously_independently_attested_native_writer_target_count']==62
assert prior['remaining_requires_separate_native_hardware_evidence']==85
assert 0 in prior['remaining_non_IFUNC_DT_RELA_indices']
assert 0 not in prior['previously_attested_original_source_indices']
g=(src/(prefix+'.gdb')).read_text()
assert g.count('watch -location *(unsigned long long *)0x8041ffc68')==1
assert g.count('x/i $pc-4\n')==1
assert g.count('KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH')==1
g=g.replace('KERNIX_G0_RELA0_RES_NATIVE_RAW_WATCH',
            'KERNIX_G0_RELA0_RES_JIT_RAW_WATCH')
addon=(
    'printf "KERNIX_G0_RELA0_NATIVE_REGS x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
    'set $hdr=*(unsigned long long *)$x28\n'
    'set $off=*(unsigned int *)$hdr\n'
    'set $tail=$hdr+$off\n'
    'set $entry=*(unsigned long long *)($tail+8)\n'
    'set $size=*(unsigned long long *)($tail+16)\n'
    'set $cnt=*(unsigned int *)($tail+24)\n'
    'printf "KERNIX_G0_RELA0_FEX_ORIGINAL_SOURCE_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
    'x/16bx $entry\n'
)
g=g.replace('x/i $pc-4\n','x/i $pc-4\n'+addon)
assert g.count('KERNIX_G0_RELA0_RES_JIT_RAW_WATCH')==1
assert g.count('KERNIX_G0_RELA0_FEX_ORIGINAL_SOURCE_JIT')==1
out=Path('dist/original-libc-DT-RELA0-R_X86_64_64-_res-REAL-ARM64-FEX-JIT-RAW-NATIVE-WRITER.gdb')
out.write_text(g)
print('KERNIX_G0_ORIGINAL_GNU_RELA0_NATIVE_JIT_AARCH64_STLR_X13_X4_CANDIDATE_SOURCE_ONLY_NO_PROOF_62_OF_147')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
tag='dist/original-libc-DT-RELA0-R_X86_64_64-_res-REAL-ARM64-FEX-JIT-RAW-NATIVE-WRITER'
set +e
timeout -k 5s 180s gdb -q -nx -batch -x "$tag.gdb" \
  --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
  "$PWD/dist/original-source-pinned-root" >"$tag.log" 2>&1
rc=$?
set -e
echo "$rc" >"$tag.exit"
python3 - <<'PY'
import hashlib,json,re
from pathlib import Path
prefix='original-libc-DT-RELA0-R_X86_64_64-_res-REAL-ARM64-FEX-JIT-RAW-NATIVE-WRITER'
root=Path('dist')
log=(root/(prefix+'.log')).read_text(errors='replace')
rc=int((root/(prefix+'.exit')).read_text().strip())
hit=re.search(r'KERNIX_G0_RELA0_RES_JIT_RAW_WATCH target=0x8041ffc68 pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+)',log)
regs=re.search(r'KERNIX_G0_RELA0_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)',log)
jit=re.search(r'KERNIX_G0_RELA0_FEX_ORIGINAL_SOURCE_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)',log)
data={
 'schema':'kernix.g0.gnu-rela0-res-real-fex-native-stlr-source-jit-raw.v1',
 'original_source_index':0,
 'original_relocation_type':'R_X86_64_64',
 'original_source_target':'0x8041ffc68',
 'original_source_symbol_name':'_res',
 'original_source_symbol_bss_candidate':'0x80420b680',
 'old_source_zero_qword':'0x0',
 'raw_arm64_hardware_marker_seen':bool(hit),
 'raw_fex_native_x4_x13_registers_seen':bool(regs),
 'native_x4_target_candidate':bool(regs and regs.group(1)=='0x8041ffc68'),
 'native_x13_symbol_value_candidate':bool(regs and regs.group(2)=='0x80420b680'),
 'raw_original_GNU_x86_JIT_guest_entry_seen':bool(jit),
 'jit_original_guest_entry_candidate':jit.group(1) if jit else None,
 'jit_original_guest_source_size_candidate':jit.group(2) if jit else None,
 'jit_native_count_candidate':int(jit.group(3)) if jit else None,
 'native_arm64_STLR_x13_x4_disassembly_seen':bool(re.search(r'\bstlr\s+x13,\s*\[x4\]',log,re.I)),
 'gdb_process_exit_code':rc,
 'raw_log_sha256':hashlib.sha256(log.encode()).hexdigest(),
 'native_source_hardware_writer_independently_attested':False,
 'original_GNU_R_X86_64_64_symbol_preemption_and_version_lookup_proven':False,
 'original_GNU_R_X86_64_64_guest_x86_store_JIT_independently_proven':False,
 'prior_real_independent_original_writer_count':62,
 'all_147_same_guest_relocations_proven':False,
 'Android_Bionic_Wine_Proton_games_proven':False,
}
assert len(log)>200
(root/(prefix+'.json')).write_text(json.dumps(data,indent=2)+'\n')
print('KERNIX_G0_ORIGINAL_GNU_RELA0_NATIVE_SOURCE_JIT_STLR_RAW_ONLY_KEEP_62_147',json.dumps(data,sort_keys=True))
PY
tail -n 85 "$tag.log"
echo KERNIX_G0_ORIGINAL_GNU_RELA0_SOURCE_JIT_OBSERVATION_ONLY_NO_NEW_INDEPENDENT_WRITER_62_147
