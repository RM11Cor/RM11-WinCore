#!/usr/bin/env python3
"""One of twenty independent concurrently scheduled original GNU FEX ARM64 cases.

Each matrix job owns exactly ONE original GNU DT_RELA source index and executes
WATCH and AWATCH in two separate FEX/GDB processes with independent GDB logs.
One job's failure does not block the other 19. NEVER certify same-process
relocation closure from separate Linux processes or from raw logs alone.
"""
from __future__ import annotations
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
from kernix_g0_parallel20_original_gnu_source_plan import SCHEMA as SOURCE_SCHEMA,OUT as SOURCE_OUT,INDICES
SCHEMA="kernix.g0.parallel20.original-rela65-84-one-isolated-arm64-fex-case-raw-two-gdb-modes.v1"
MODES=("watch","awatch")
def need(ok,msg):
    if not ok:raise AssertionError("KERNIX_G0_PARALLEL20_GNU_CASE_FAIL_CLOSED: "+msg)
def regular(p:Path,maximum=3000000):
    need(p.is_file() and not p.is_symlink(),"real regular original artifact "+str(p))
    v=p.read_bytes()
    need(0<len(v)<=maximum,"bounded original immutable artifact "+str(p))
    return v

def instrument(original:str,index:int,target:str,mode:str)->str:
    need(mode in MODES and index in INDICES and original.count("watch -location *(unsigned long long *)"+target)==1,
         "only original source GDB watch at exactly this index")
    original_arm=f"KERNIX_G0_ORIGINAL_RELA{index}_RAW_HIT"
    need(original.count(original_arm)==1 and original.count("x/i $pc-4\n")==1,
         "original GNU ELF source GDB native hit marker and disassembler")
    marker=f"KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}_RAW_HIT"
    script=original.replace(original_arm,marker)
    if mode=="awatch":
        script=script.replace("watch -location *(unsigned long long *)"+target,
                              "awatch -location *(unsigned long long *)"+target)
    addon=(
      f'printf "KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}_NATIVE_REGS x4=0x%lx x13=0x%lx x28=0x%lx\\n",$x4,$x13,$x28\n'
      'set $hdr=*(unsigned long long *)$x28\n'
      'set $off=*(unsigned int *)$hdr\n'
      'set $tail=$hdr+$off\n'
      'set $entry=*(unsigned long long *)($tail+8)\n'
      'set $size=*(unsigned long long *)($tail+16)\n'
      'set $cnt=*(unsigned int *)($tail+24)\n'
      f'printf "KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}_FEX_JIT guest_entry=0x%lx source_size=0x%lx native_count=%u\\n",$entry,$size,$cnt\n'
      'x/16bx $entry\n'
    )
    script=script.replace("x/i $pc-4\n","x/i $pc-4\n"+addon)
    need(script.count(marker)==1
         and script.count(f"KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}_NATIVE_REGS")==1
         and script.count(f"KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}_FEX_JIT")==1,
         "exactly one original ELF source, JIT and real ARM64 GDB breakpoint")
    return script

def capture_one(mode:str,index:int,row:dict,source:Path,triad:Path,exe:Path,out:Path):
    base=out/mode
    origin=regular(source).decode()
    gdb=instrument(origin,index,row["target"],mode)
    (base.with_suffix(".gdb")).write_text(gdb)
    cmd=["timeout","-k","5s","165s","gdb","-q","-nx","-batch",
         "-x",str(base.with_suffix(".gdb")),"--args",str(exe),str(triad)]
    try:
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                         timeout=185,check=False)
        log=p.stdout.decode(errors="replace")
        rc=p.returncode
    except subprocess.TimeoutExpired as e:
        rc=124
        log=(e.stdout or b"").decode(errors="replace")+"\nKERNIX_G0_PARALLEL20_GDB_TIMEOUT\n"
    (base.with_suffix(".log")).write_text(log)
    (base.with_suffix(".exit")).write_text(str(rc)+"\n")
    prefix=f"KERNIX_G0_PARALLEL20_RELA{index}_{mode.upper()}"
    hw_kind="Hardware watchpoint 2:" if mode=="watch" else "Hardware access (read/write) watchpoint 2:"
    hw_count=len(re.findall("^"+re.escape(hw_kind)+" -location "+re.escape("*(unsigned long long *)"+row["target"])+r"$",
                            log,re.M))
    regs=re.search("^"+prefix+r"_NATIVE_REGS x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+)$",log,re.M)
    jit=re.search("^"+prefix+r"_FEX_JIT guest_entry=(0x[0-9a-f]+) source_size=(0x[0-9a-f]+) native_count=(\d+)$",log,re.M)
    hit=re.search("^"+prefix+r"_RAW_HIT target=(0x[0-9a-f]+) pc=(0x[0-9a-f]+) x4=(0x[0-9a-f]+) x13=(0x[0-9a-f]+) x28=(0x[0-9a-f]+) NOT_CERTIFIED=1$",log,re.M)
    memory_readback=re.search(r"^"+re.escape(row["target"])+r":\s+(0x[0-9a-f]+)$",log,re.M)
    # Independent real-aarch64 GDB trace checks, still raw-only, not
    # substitute for a separately executed independent evidence audit.
    native_store=re.search(r"^\s*(0x[0-9a-f]+):\s+stlr\s+x13,\s*\[x4\]",log,re.M)
    source_elf=re.search(r"^KERNIX_G0_ORIGINAL_RELA"+str(index)+r"_SOURCE_ARM type="+row["source_type"]+
                        r" target="+re.escape(row["target"])+r" initial=0x0 SOURCE_ONLY=1$",log,re.M)
    final_source=re.search(r"^KERNIX_G0_ORIGINAL_RELA"+str(index)+r"_ZERO_NATIVE_CERTIFICATION_FROM_SOURCE_DISCOVERY=1$",log,re.M)
    value=(regs.group(2) if regs else None)
    expected=row["expected_candidate_plus_signed_addend_if_defined"]
    candidate_valid=(expected is not None and value==expected)
    native_valid=(hit is not None and regs is not None and jit is not None and native_store is not None
        and int(hit.group(2),16)==int(native_store.group(1),16)+4
        and hit.group(1)==regs.group(1)==row["target"]
        and hit.group(3)==regs.group(1)
        and hit.group(4)==regs.group(2)
        and hit.group(5)==regs.group(3)
        and int(regs.group(3),16)>=0xffff00000000
        and int(native_store.group(1),16)>=0xffff00000000
        and jit.group(1)=="0x80100fb8b" and jit.group(2)=="0x3" and int(jit.group(3))==2
        and re.search(r"^0x80100fb8b:\s+0x4c\s+0x89\s+0x08",log,re.M) is not None)
    passed=(rc==0 and source_elf is not None and final_source is not None
            and hw_count==2 and native_valid and candidate_valid)
    result={
       "schema":SCHEMA,"original_source_index":index,"source_type":row["source_type"],
       "original_symbol_name":row["symbol_name"],"original_source_target":row["target"],
       "mode":mode,"native_gdb_exit_code":rc,"hardware_watchpoint_definition_and_hit_count":hw_count,
       "original_source_marker_observed":bool(source_elf),"raw_native_STLR_register_JIT_checks":bool(native_valid),
       "original_GNU_symbol_candidate_with_signed_addend_matches":bool(candidate_valid),
       "expected_candidate":expected,"actual_live_native_x13":value,
       "original_guest_source_footer_observed":bool(final_source),
       "raw_capture_complete":bool(passed),
       "raw_GDB_original_trace_sha256":hashlib.sha256(log.encode()).hexdigest(),
       "independently_certified_from_this_raw_job":False,
       "same_guest_process_20_targets_proven":False,
       "all_147_same_guest_native_execution_proven":False,
       "Android_Bionic_Wine_Proton_games_proven":False,
    }
    (base.with_suffix(".json")).write_text(json.dumps(result,indent=2)+"\n")
    print(f"KERNIX_G0_PARALLEL20_CASE index={index} mode={mode} raw_pass={passed} rc={rc} "
          f"HW={hw_count} target={row['target']} expected={expected} actual={value}",flush=True)
    return result

def run(index:int,pack:Path,out:Path):
    need(index in INDICES,"20 independently original source indices 65..84")
    source=pack/"source"
    original=pack/"original-source-pinned-root"
    exe=pack/"kernix-g0-original-fex-main-actual-mprotect10-linux-arm64"
    core=pack/"FEXCore-lib"
    need(exe.is_file() and not exe.is_symlink() and original.is_dir(),"compiled original FEX and ELF true guest triad")
    need((core/"libFEXCore.so").is_file(),"shared SHA-pinned Linux ARM64 FEX core")
    manifest=json.loads(regular(source/SOURCE_OUT))
    need(manifest["schema"]==SOURCE_SCHEMA
         and manifest["original_source_indices"]==INDICES
         and manifest["max_parallel_original_gdb_case_jobs"]==20
         and manifest["new_certified_individual_source_writers"]==0
         and manifest["same_guest_process_20_targets_proven"] is False,
         "original source-only canonical 147 ledger, matrix runner never certifies itself")
    rows=manifest["twenty_independently_isolated_GNU_source_targets"]
    row=rows[index-INDICES[0]]
    need(row["index"]==index and row["source_type"] in ("R_X86_64_GLOB_DAT","R_X86_64_64"),
         "matrix index matches exactly one original GNU tuple")
    original_gdb=source/row["source_gdb_script"]
    need(hashlib.sha256(regular(original_gdb)).hexdigest()==row["source_gdb_sha256"],
         "original GNU source GDB exact manifest SHA")
    out.mkdir(parents=True,exist_ok=True)
    data={
        "schema":SCHEMA,"index":index,"original_source_type":row["source_type"],
        "symbol_name":row["symbol_name"],"target":row["target"],
        "two_separate_native_FEX_GDB_process_modes":list(MODES),
        "raw_complete_for_both_modes":False,"mode_results":{},
        "previous_original_GNU_source_writers_independently_certified":147,
        "new_native_original_writer_certifications":0,
        "same_guest_process_20_targets_proven":False,
        "all_147_same_guest_native_execution_proven":False,
        "Android_Bionic_Wine_Proton_games_proven":False,
    }
    try:
        for mode in MODES:
            data["mode_results"][mode]=capture_one(mode,index,row,original,original_gdb,exe,out)
        data["raw_complete_for_both_modes"]=all(
            data["mode_results"][mode]["raw_capture_complete"] for mode in MODES)
    except Exception as error:
        data["error_type"]=type(error).__name__
        data["error"]=str(error)[:650]
        print(f"KERNIX_G0_PARALLEL20_ISOLATED_CASE_{index}_ERROR {type(error).__name__}: {error}",flush=True)
    (out/"index-raw-result.json").write_text(json.dumps(data,indent=2)+"\n")
    print("KERNIX_G0_PARALLEL20_INDIVIDUAL_CASE index="+str(index)+
          " RAW_CAPTURE="+("COMPLETE" if data["raw_complete_for_both_modes"] else "FAIL_CLOSED")
          +" OTHER_19_CASES_NOT_BLOCKED NEW_NATIVE_CERTIFICATIONS_ZERO",flush=True)
    return data

if __name__=="__main__":
    need(len(sys.argv)==4,"usage one_original_GNU_source_index_65_to_84 shared_authentic_FEX_bundle one_case_output")
    result=run(int(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
    sys.exit(0 if result["raw_complete_for_both_modes"] else 2)
