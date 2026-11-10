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
chainpath=Path('inputs/ifunc85-original-x86-zero-return-chain/original-libc-IFUNC85-zero-return-source-and-GNU-ldso-call-store-NO-NATIVE.json')
assert chainpath.is_file() and not chainpath.is_symlink()
chain=json.loads(chainpath.read_text())
assert chain['original_source_libc_sha256']==LIBC_SHA
assert chain['original_source_ldso_sha256']==LDSO_SHA
assert chain['source_index']==85 and chain['source_table']=='DT_RELA'
assert chain['original_target_initial_qword']=='0x0'
assert chain['original_guest_target']==hex(target)
assert chain['original_x86_zero_return_opcode']=='31c0'
assert chain['original_x86_ret_opcode']=='c3'
assert chain['original_x86_GNU_ldso_resolver_call_opcode']=='ffd0'
assert chain['original_x86_GNU_ldso_store_opcode']=='498906'
assert chain['original_x86_GNU_ldso_store_guest_address']=='0x80100fd60'
assert chain['previous_independently_attested_original_writer_count']==61
assert chain['new_real_native_writer_attestations']==0
assert chain['source_GNU_loader_STORE_executed_under_ARM64_FEX_proven'] is False
(Path('dist')/chainpath.name).write_bytes(chainpath.read_bytes())
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

# A second, separate FEX x86 guest process uses hardware ACCESS watchpoints.
# AArch64 fixture proves 'watch' may miss zero-to-zero STLR while 'awatch' traps.
# An awatch can also trap on READS; every observed access must be independently
# linked to a native STORE and the SHA-pinned original guest source before proof.
python3 - <<'PY'
import json,hashlib
from pathlib import Path
root=Path('dist')
source=root/'original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.gdb'
p=json.loads((root/'original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.json').read_text())
target=p['original_guest_target']
gdb=source.read_text()
old=f'watch -location *(unsigned long long *){target}'
new=f'awatch -location *(unsigned long long *){target}'
assert gdb.count(old)==1 and 'awatch -location' not in gdb
new_script=gdb.replace(old,new).replace(
  'KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT',
  'KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS')
# For this special original DT_RELA zero-result resolver, capture the
# actual native stored register and the ORIGINAL x86 STORE JIT source in this
# same FEX guest/watch process. Source checks never count as native proof.
oldprint=r'pc=0x%lx x19=0x%lx RAW_NOT_INDEPENDENT=1\n",$pc,$x19'
newprint=r'pc=0x%lx guest_x4=0x%lx x19=0x%lx x28=0x%lx RAW_NOT_INDEPENDENT=1\n",$pc,$x4,$x19,$x28'
assert new_script.count(oldprint)==1
new_script=new_script.replace(oldprint,newprint)
native_jit=(
  'set $hdr=*(unsigned long long *)$x28\n'
  'set $off=*(unsigned int *)$hdr\n'
  'set $tail=$hdr+$off\n'
  'set $entry=*(unsigned long long *)($tail+8)\n'
  'set $size=*(unsigned long long *)($tail+16)\n'
  'set $cnt=*(unsigned int *)($tail+24)\n'
  'printf "KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
  'x/3bx $entry\n'
  'x/3bx 0x80100fd60\n'
  'x/3bx 0x8040c860b\n'
)
assert new_script.count('x/i $pc-4\n')==1
new_script=new_script.replace('x/i $pc-4\n','x/i $pc-4\n'+native_jit)
assert new_script.count(new)==1
assert 'KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS' in new_script
assert new_script.startswith('set pagination off\nset confirm off\n')
out=root/'original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS.gdb'
out.write_text(new_script)
print('KERNIX_G0_IFUNC85_DTRELA_AARCH64_AWATCH_RAW_ACCESS_ARMED_NO_WRITER_CERTIFICATION')
PY
tag2="dist/original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS"
test -s "$tag2.gdb"
set +e
timeout -k 5s 180s gdb -q -nx -batch \
  -x "$tag2.gdb" \
  --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
  "$PWD/dist/original-source-pinned-root" \
  >"$tag2.log" 2>&1
rc2=$?
set -e
echo "$rc2" >"$tag2.exit"
python3 - <<'PY'
import json,hashlib,re
from pathlib import Path
root=Path('dist')
plan=json.loads((root/'original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.json').read_text())
stem='original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-RAW-ACCESS'
log=(root/(stem+'.log')).read_text(errors='replace')
rc=int((root/(stem+'.exit')).read_text().strip())
target=plan['original_guest_target']
arm='KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target='+target
access='KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_ACCESS target='+target
armpos=log.find(arm)
accesspos=log.find(access)
armqword=bool(re.search(re.escape(target)+r':\s+0x0{16}',log))
triggers=re.findall(r'Hardware access \(read/write\) watchpoint 2:',log)
obj={
  'schema':'kernix.g0.original-ifunc85-dt-rela-zero-real-arm64-fex-access-watch-diagnostic.v1',
  'original_source_index':85,
  'original_table':'DT_RELA',
  'original_source_target':target,
  'original_qword_zero_at_access_watch_arm_observed':bool(armqword and armpos>=0),
  'native_arm64_hardware_access_watch_installed':bool(len(triggers)>=1),
  'native_arm64_hardware_access_watch_trapped':bool(len(triggers)>=2),
  'raw_hardware_access_guest_pc_register_marker_observed':bool(accesspos>armpos>=0),
  'arm64_native_instruction_text_exposes_stlr':bool(re.search(r'\bstlr\s+',log,re.I)),
  'native_x4_zero_and_x19_exact_original_target_raw_candidate':bool(
     re.search(r'RAW_UNVERIFIED_ACCESS target='+re.escape(target)+
               r' pc=0x[0-9a-f]+ guest_x4=0x0 x19='+
               re.escape(target)+r' x28=0x[0-9a-f]+ RAW_NOT_INDEPENDENT=1',log)),
  'same_guest_original_x86_GNU_STORE_source_JIT_header_observed':bool(
     re.search(r'KERNIX_G0_IFUNC85_DTRELA_SOURCE_GNU_JIT '
               r'guest_entry=0x80100fd60 source_size=0x3 native_count=2',log)),
  'two_original_target_zero_qword_samples_arm_and_post_trap':bool(
     len(re.findall(re.escape(target)+r':\s+0x0{16}',log))>=2),
  'actual_original_GNU_zero_same_value_store_independent_proof_pending':True,
  'arm64_native_instruction_text_exposes_str':bool(re.search(r'\bstr\s+',log,re.I)),
  'native_hardware_write_independently_attested':False,
  'raw_access_includes_reads_not_automatically_a_writer':True,
  'native_source_guest_STORE_JIT_not_yet_independently_attested':True,
  'candidate_gdb_exit_code':rc,
  'log_sha256':hashlib.sha256(log.encode()).hexdigest(),
  'log_length':len(log),
  'original_GNU_native_writer_ledger_unchanged':61,
  'Android_Bionic_Wine_Proton_games_proven':False,
}
assert target.startswith('0x804') and len(log)>100
(root/(stem+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
print('KERNIX_G0_IFUNC85_DT_RELA_REAL_ARM64_AWATCH_ACCESS_CANDIDATE_NO_NATIVE_CERTIFICATION',json.dumps(obj,sort_keys=True))
PY
tail -n 90 "$tag2.log"
echo KERNIX_G0_IFUNC85_ORIGINAL_DTRELA_AWATCH_MAY_BE_READ_OR_WRITE_HOLD_NATIVE_61_147

