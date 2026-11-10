#!/usr/bin/env bash
# Original GNU libc IFUNC85 DT_RELA ZERO-to-ZERO: third FEX guest AWATCH
# for x86 source JIT provenance. RAW ONLY: never increase 61/147 here.
set -euo pipefail
mkdir -p dist
python3 - <<'PY'
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'native-engine/tools')
from kernix_g0_original_libc_relocation_type_transition_gate import LIBC_SHA,LDSO_SHA,decode_original_libc
from kernix_g0_next_libc_symbolic_live_writer_gate import source_offset
from kernix_g0_first_libc_ifunc102_original_fex_source_watch import STORE,LDSO_BIAS
root=Path('dist/original-source-pinned-root')
libc=(root/'lib/x86_64-linux-gnu/libc.so.6').read_bytes()
ldso=(root/'lib64/ld-linux-x86-64.so.2').read_bytes()
assert len(libc)==2118168 and hashlib.sha256(libc).hexdigest()==LIBC_SHA
assert len(ldso)==235408 and hashlib.sha256(ldso).hexdigest()==LDSO_SHA
row=decode_original_libc(libc)[85]
assert (row['index'],row['table'],row['table_index'],row['r_type'],row['r_sym'])==(85,'DT_RELA',85,37,0)
assert row['original_source_qword']=='0x0'
target=row['source_guest_target']
assert target=='0x8042014c8'
offset=source_offset(ldso,STORE-LDSO_BIAS,3,5)
assert ldso[offset:offset+3]==bytes.fromhex('498906')
p=Path('inputs/ifunc85-dt-rela-source-only/original-libc-IFUNC85-DT_RELA-zero-source-only-NO-NATIVE-PROOF.gdb')
assert p.is_file() and not p.is_symlink()
g=p.read_text()
assert g.startswith('set pagination off\nset confirm off\n')
assert g.count('watch -location *(unsigned long long *)'+target)==1
assert 'awatch -location' not in g
g=g.replace('watch -location *(unsigned long long *)'+target,
            'awatch -location *(unsigned long long *)'+target)
g=g.replace('KERNIX_G0_IFUNC85_DT_RELA_RAW_UNVERIFIED_HIT',
            'KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT')
anchor='x/i $pc-4\n'
assert g.count(anchor)==1
inject=(
  'printf "KERNIX_G0_IFUNC85_NATIVE_REGS x4=0x%lx x19=0x%lx x28=0x%lx\\n",$x4,$x19,$x28\n'
  'set $hdr=*(unsigned long long *)$x28\n'
  'set $off=*(unsigned int *)$hdr\n'
  'set $tail=$hdr+$off\n'
  'set $entry=*(unsigned long long *)($tail+8)\n'
  'set $size=*(unsigned long long *)($tail+16)\n'
  'set $cnt=*(unsigned int *)($tail+24)\n'
  'printf "KERNIX_G0_IFUNC85_SOURCE_GNU_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
  'x/8bx $entry\n'
  f'x/8bx {hex(STORE)}\n'
)
g=g.replace(anchor,anchor+inject)
assert g.count('awatch -location *(unsigned long long *)'+target)==1
assert g.count('KERNIX_G0_IFUNC85_SOURCE_GNU_JIT')==1
out=Path('dist/original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-JIT-RAW-AWATCH.gdb')
out.write_text(g)
print('KERNIX_G0_IFUNC85_GENUINE_GNU_SOURCE_SHA_ZERO_QWORD_JIT_AWATCH_CANDIDATE_READY_RAW_ONLY_61_147')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
tag="dist/original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-JIT-RAW-AWATCH"
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
tag=Path('dist/original-libc-IFUNC85-DT_RELA-zero-REAL-ARM64-FEX-JIT-RAW-AWATCH')
raw=tag.with_suffix('.log').read_text(errors='replace')
rc=int(tag.with_suffix('.exit').read_text().strip())
target='0x8042014c8'
arm=raw.find('KERNIX_G0_IFUNC85_DT_RELA_CANDIDATE_PREWATCH target='+target)
hit=raw.find('KERNIX_G0_IFUNC85_DT_RELA_JIT_RAW_AWATCH_HIT target='+target)
m=re.search(r'KERNIX_G0_IFUNC85_SOURCE_GNU_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)',raw)
regs=re.search(r'KERNIX_G0_IFUNC85_NATIVE_REGS x4=(0x[0-9a-f]+) x19=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)',raw)
actual_events=len(re.findall(r'^Hardware access \\(read/write\\) watchpoint 2:',raw,re.M))
obj={
 'schema':'kernix.g0.original-ifunc85-dt-rela-zero-raw-awatch-native-jit-source-probe.v1',
 'original_source_target':target,
 'original_source_qword':'0x0',
 'source_ONLY_prior_61_native_writers':61,
 'process_gdb_exit_code':rc,
 'hardware_AWATCH_actual_after_arm_marker_seen':hit>arm>=0,
 'arm_zero_live_qword_seen':bool(re.search(re.escape(target)+r':\s+0x0{16}',raw)),
 'native_store_arm64_stlr_x4_x19_visible':bool(re.search(r'\bstlr\s+x4,\s*\[x19\]',raw,re.I)),
 'native_FEX_guest_JIT_entry_marker_seen':bool(m),
 'genuine_hardware_access_event_after_arming':actual_events>=2 and hit>arm>=0,
 'native_x4_zero_candidate':bool(regs and regs.group(1)=='0x0'),
 'native_x19_equals_original_source_target_candidate':bool(regs and regs.group(2)==target),
 'original_GNU_x86_store_JIT_entry_candidate':bool(m and m.group(1)=='0x80100fd60' and m.group(2)=='0x3' and int(m.group(3))>=1),
 'awatch_READ_or_WRITE_not_independently_classified':True,
 'candidate_guest_JIT_entry':m.group(1) if m else None,
 'raw_log_sha256':hashlib.sha256(raw.encode()).hexdigest(),
 'native_hardware_writer_independently_attested':False,
 'original_dt_rela_x86_guest_store_proven_by_this_RAW_probe':False,
 'all_147_same_guest_proven':False,
 'Android_Bionic_Wine_Proton_games_proven':False,
 'remain_61_independent_native_writer_targets':True,
}
tag.with_suffix('.json').write_text(json.dumps(obj,indent=2)+'\n')
print('KERNIX_G0_IFUNC85_REAL_GNU_ARM64_JIT_AWATCH_RAW_DO_NOT_CERTIFY',json.dumps(obj,sort_keys=True))
PY
tail -n 95 "$tag.log"
echo KERNIX_G0_IFUNC85_REAL_GNU_JIT_AWATCH_SOURCE_STORE_PENDING_INDEPENDENT_ATTESTATION_KEEP_61_OF_147
