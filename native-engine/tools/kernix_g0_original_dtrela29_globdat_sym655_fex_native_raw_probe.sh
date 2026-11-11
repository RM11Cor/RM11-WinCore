#!/usr/bin/env bash
# Original GNU x86 libc DT_RELA29 R_X86_64_GLOB_DAT sym655 addend0 __curbrk.
# Real Linux AArch64 FEX GDB WATCH and AWATCH, separate guest runs, RAW ONLY.
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
r=decode_original_libc(libc)[29]
assert (r['index'],r['table'],r['table_index'],r['r_type'],r['r_sym'],r['r_offset'],r['r_addend'],r['original_source_qword'])==(29,'DT_RELA',29,6,655,'0x202e48',0,'0x0')
assert r['source_guest_target']=='0x804202e48'
off=source_offset(libc,0x202e48,8,6,nonexec=True)
assert libc[off:off+8]==bytes(8)
src=Path('inputs/dt-rela29-globdat-source')
stem='original-libc-DT-RELA29-next-actual-source-type-symbol-hardware-writer-NO-NATIVE-PROOF'
p=src/(stem+'.json');g=src/(stem+'.gdb')
assert p.is_file() and g.is_file() and not p.is_symlink() and not g.is_symlink()
d=json.loads(p.read_text())
assert d['original_source_libc_sha256']==LIBC_SHA and d['original_source_ldso_sha256']==LDSO_SHA
assert d['original_source_index']==29 and d['original_table']=='DT_RELA'
assert d['original_relocation_type']=='R_X86_64_GLOB_DAT'
assert d['original_source_signed_addend']==0 and d['original_source_relocation_offset']=='0x202e48'
assert d['original_symbol']['symbol_index']==655 and d['original_symbol']['symbol_name']=='__curbrk' and d['original_symbol']['source_definition_address_candidate_if_non_TLS']=='0x80420ad70' and d['original_symbol']['source_definition_in_BSS_if_PT_LOAD_known'] is True and d['original_symbol']['runtime_symbol_lookup_or_versioned_preemption_proven'] is False
assert d['original_guest_target']=='0x804202e48' and d['original_source_initial_qword']=='0x0'
assert d['original_91_native_source_writers_independently_attested']==91
assert d['new_native_writer_target_evidence_from_this_source_discovery']==0
assert d['original_symbol']['TLS_runtime_address_or_module_offset_proven'] is False
prev=Path('inputs/previous91-ledger/original-libc-147-source-batch-native-proof-ledger91-NO-NEW-HW-RUN.json')
assert prev.is_file() and not prev.is_symlink()
ledger=json.loads(prev.read_text())
assert ledger['previously_independently_attested_native_writer_target_count']==91
assert ledger['remaining_requires_separate_native_hardware_evidence']==56
assert ledger['remaining_non_IFUNC_DT_RELA_indices']==list(range(29,85))
assert 29 not in ledger['previously_attested_original_source_indices']
assert ledger['native_GNU_DT_RELA0_R64_res_REAL_FEX_ARM64_JIT_source_store_writer_independently_proven'] is True
assert ledger['native_GNU_DT_RELA1_TLS_TPOFF64_sym0_addend56_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA2_TLS_TPOFF64_sym0_addend48_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA3_TLS_TPOFF64_sym0_addend88_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA4_TLS_TPOFF64_sym0_addend72_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA5_TLS_TPOFF64_sym0_addend80_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA6_TLS_TPOFF64_sym0_addend100_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA7_TLS_TPOFF64_sym0_addend120_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA8_TLS_TPOFF64_sym0_addend128_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA9_TLS_TPOFF64_sym0_addend24_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA10_TLS_TPOFF64_sym0_addend40_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA15_TLS_TPOFF64_sym0_addend32_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA16_GLOBDAT_sym3013_svc_max_pollfd_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA17_GLOBDAT_sym72_obstack_alloc_failed_handler_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA20_GLOBDAT_sym1__dl_argv_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA22_GLOBDAT_sym516_free_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA23_GLOBDAT_sym490_re_syntax_options_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA24_GLOBDAT_sym51_rpc_createerr_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA25_GLOBDAT_sym1570_stdout_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA26_GLOBDAT_sym1250___ctype32_toupper_REAL_FEX_ARM64_STORE_independently_proven'] is True
assert ledger['native_GNU_DT_RELA27_GLOBDAT_sym2646_opterr_REAL_FEX_ARM64_STORE_independently_proven'] is True
original=g.read_text()
target='0x804202e48'
assert original.count('watch -location *(unsigned long long *)'+target)==1
assert original.count('x/i $pc-4\n')==1
assert original.count('KERNIX_G0_ORIGINAL_RELA29_NEXT_RAW_HIT')==1
for mode in ('watch','awatch'):
    work=original.replace('KERNIX_G0_ORIGINAL_RELA29_NEXT_RAW_HIT',
                          'KERNIX_G0_RELA29_'+mode.upper()+'_RAW_HIT')
    if mode=='awatch':
        work=work.replace('watch -location *(unsigned long long *)'+target,
                          'awatch -location *(unsigned long long *)'+target)
    code=(
      'printf "KERNIX_G0_RELA29_GLOBDAT_SYM655_NATIVE_REGS x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      'printf "KERNIX_G0_RELA29_GLOBDAT_SYM655_FEX_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/16bx $entry\n'
    )
    work=work.replace('x/i $pc-4\n','x/i $pc-4\n'+code)
    assert work.count(mode+' -location *(unsigned long long *)'+target)==1
    assert work.count('KERNIX_G0_RELA29_GLOBDAT_SYM655_FEX_JIT')==1
    out=Path('dist')/('original-libc-DT-RELA29-GLOBDAT-SYM655-REAL-ARM64-FEX-'+mode+'-JIT-RAW.gdb')
    out.write_text(work)
    print('KERNIX_G0_ORIGINAL_RELA29_GLOBDAT_SYM655_GDB',mode,'SOURCE_ONLY_LEDGER91=1')
PY
CORE="$(find /tmp/kernix-g2ec2-fex-native -type f -name libFEXCore.so | head -1)"
test -s "$CORE"
export LD_LIBRARY_PATH="$(dirname "$CORE")"
test -s "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
for mode in watch awatch; do
  stem="dist/original-libc-DT-RELA29-GLOBDAT-SYM655-REAL-ARM64-FEX-$mode-JIT-RAW"
  set +e
  timeout -k 5s 180s gdb -q -nx -batch -x "$stem.gdb" \
    --args "$PWD/dist/kernix-g0-original-fex-main-actual-mprotect10-linux-arm64" \
    "$PWD/dist/original-source-pinned-root" >"$stem.log" 2>&1
  rc=$?
  set -e
  echo "$rc" >"$stem.exit"
  python3 - "$stem" "$mode" <<'PY'
import sys,json,hashlib,re
from pathlib import Path
stem,mode=sys.argv[1],sys.argv[2]
p=Path(stem)
log=p.with_suffix('.log').read_text(errors='replace')
rc=int(p.with_suffix('.exit').read_text().strip())
target='0x804202e48'
arm=log.find('KERNIX_G0_ORIGINAL_RELA29_NEXT_SOURCE_ARM type=R_X86_64_GLOB_DAT target='+target)
hit=log.find('KERNIX_G0_RELA29_'+mode.upper()+'_RAW_HIT target='+target)
marker=('Hardware access (read/write) watchpoint 2:' if mode=='awatch' else 'Hardware watchpoint 2:')
events=len(re.findall(r'^'+re.escape(marker)+r' -location \*\(unsigned long long \*\)'+target+'$',log,re.M))
regs=re.search(r'KERNIX_G0_RELA29_GLOBDAT_SYM655_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)',log)
jit=re.search(r'KERNIX_G0_RELA29_GLOBDAT_SYM655_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)',log)
o=re.search(r'^Old value = (-?\d+)$',log,re.M)
n=re.search(r'^New value = (-?\d+)$',log,re.M)
data={
 'schema':'kernix.g0.original-rela29-globdat-sym655-raw-'+mode+'.v1',
 'original_index':29,'original_table':'DT_RELA',
 'original_type':'R_X86_64_GLOB_DAT','original_symbol_index':655,
 'original_signed_addend':0,
 'original_guest_target':target,'original_qword':'0x0',
 'mode':mode,'native_arm_seen':arm>=0,
 'raw_native_hardware_declaration_and_hit_count':events,
 'raw_post_arm_hardware_access_candidate':hit>arm>=0 and events>=2,
 'raw_old_qword':o.group(1) if o else None,
 'raw_new_qword':n.group(1) if n else None,
 'source_only_candidate_must_not_replace_observed_native_qword':True,
 'raw_native_x4':regs.group(1) if regs else None,
 'raw_native_x13':regs.group(2) if regs else None,
 'raw_FEX_JIT_original_source_guest_entry':jit.group(1) if jit else None,
 'raw_FEX_JIT_original_guest_size':jit.group(2) if jit else None,
 'original_definition_candidate_from_ELF':'0x80420ad70',
 'original_defined_symbol_name':'__curbrk',
 'runtime_binding_or_preemption_proven':False,
 'native_source_hardware_write_independently_attested':False,
 'previous_certified_native_writer_target_count':91,
 'all_147_same_guest_completed':False,
 'Android_Bionic_Wine_Proton_games_proven':False,
 'gdb_exit_code':rc,
 'real_native_fex_raw_log_sha256':hashlib.sha256(log.encode()).hexdigest(),
}
assert len(log)>150
p.with_suffix('.json').write_text(json.dumps(data,indent=2)+'\n')
print('KERNIX_G0_ORIGINAL_GNU_DTRELA29_GLOBDAT_SYM655_NATIVE_RAW_NO_CERTIFICATION',json.dumps(data,sort_keys=True))
PY
  tail -n 35 "$stem.log"
done
echo KERNIX_G0_ORIGINAL_GLOBDAT_DT_RELA29_REAL_FEX_TWO_NATIVE_RAW_GUEST_PROCESSES_KEEP_91_147
