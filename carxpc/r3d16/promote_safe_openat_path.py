#!/usr/bin/env python3
"""R3D16: bounded source-witnessed guest-stack pathname; NO fictitious openat.

R3D15 showed 4 real x86 ld.so syscalls and 3 diagnostic responses. The fourth
openat(257) takes its pathname from guest RSP-adjacent stack memory. Inspect
only own mapped 64KiB stack, then STOP for a real VFS implementation. Earlier
07D/07E/07F/07G and strict cacheless shim stay unchanged.
"""
from pathlib import Path
import re,sys
if len(sys.argv)!=2:raise SystemExit('usage: promote_safe_openat_path.py /tmp/carxpc')
app=Path(sys.argv[1]);java=app/'app/src/main/java/com/r4/carxpc'
native=app/'app/src/main/cpp/carx_r3d4_first_syscall.cpp'
activity=java/'R3D4ProbeActivity.java';main=java/'MainActivity.java'
gradle=app/'app/build.gradle';store=java/'R3D8JsonReportStore.java'
assert all(x.is_file() for x in (native,activity,main,gradle,store))
def one(s,old,new):
    n=s.count(old)
    assert n==1,('R3D16_SOURCE_ANCHOR_CHANGED',old[:100],n)
    return s.replace(old,new,1)
s=gradle.read_text()
s,n=re.subn(r'\bversionCode\s+43\b','versionCode 44',s)
assert n==1,'R3D16_EXPECTS_SIGNED_R3D15_V43'
s,n=re.subn(r"versionName\s+'[^']+'",
    "versionName '0.44-r3d16-guest-stack-openat-path-witness'",s)
assert n==1
gradle.write_text(s)
s=main.read_text()
s=one(s,'10 | R3D15 — إصلاح محاذاة FEX وفحص Batch',
      '10 | R3D16 — تشخيص مسار openat الرابع')
main.write_text(s)
s=store.read_text()
s=one(s,'"CarX_PC_R3D15_Alignment_Batch_Diagnostics_"',
      '"CarX_PC_R3D16_Openat_Path_Diagnostics_"')
store.write_text(s)
s=native.read_text()
s=one(s,'#include "carxpc/r3d13/native/strict_batch_policy.hpp"',
  '#include "carxpc/r3d13/native/strict_batch_policy.hpp"\n'
  '#include "carxpc/r3d16/native/safe_guest_stack_path.hpp"')
# This code runs ONLY in mode4, AFTER the previous 3 original-source checks.
# The already source-authenticated syscall journal is still the sole proof.
anchor='      std::snprintf(msg,sizeof(msg),"E_BATCH_UNSUPPORTED_NR_%llu",'
inject=r'''      // The guest's 4th openat pathname was not immutable ld.so PT_LOAD:
      // it points inside our own 64KiB Wine Linux ABI guest stack.
      if(Mode==4 && number==carx_r3d13::kOpenAt &&
         carx_r3d13::is_safe_missing_guest_cache_openat(dirfd,flags,mode)) {
        char guestPath[256]{};
        if(carx_r3d16::capture_guest_stack_ascii_path(arg1,guestPath)) {
          const size_t length=std::strlen(guestPath);
          if(length>=1 && length<=carx_r3d16::kMaxPathBytes) {
            std::snprintf(msg,sizeof(msg),"N23_STACK_PATH_LENGTH_%zu",length);
            carx_r3d6::note(msg);
            for(size_t i=0;i<length;i+=32) {
              char hex[65]{};
              const size_t take=((length-i)<32)?(length-i):32;
              static constexpr char h[]="0123456789ABCDEF";
              for(size_t j=0;j<take;++j) {
                const unsigned char c=static_cast<unsigned char>(guestPath[i+j]);
                hex[2*j]=h[c>>4];hex[2*j+1]=h[c&15];
              }
              std::snprintf(msg,sizeof(msg),"N23_STACK_PATH_HEX_%02zu_%s",
                            i/32,hex);
              carx_r3d6::note(msg);
            }
            carx_r3d6::note("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS");
            ::_exit(117);
          }
        }
        carx_r3d6::note("E_BATCH_GUEST_STACK_PATH_UNREADABLE");
        ::_exit(118);
      }
'''
s=one(s,anchor,inject+anchor)
assert all(x in s for x in ['context->ExecuteThread(thread)',
  'N22_BATCH_RETURN_OPENAT_CACHE_ENOENT',
  'E_BATCH_UNSUPPORTED_NR_','N23_STACK_PATH_HEX_'])
native.write_text(s)
s=activity.read_text()
s=one(s,'runCacheless.setText("تشغيل 07H — Batch مع إصلاح محاذاة FEX");',
      'runCacheless.setText("تشغيل 07H — R3D16 فحص مسار openat");')
s=one(s,'"r4.carx.r3d15.align-safe-original-ldso-syscall-batch.v1"',
      '"r4.carx.r3d16.stack-path-source-locked-openat-batch.v1"')
s=one(s,'"07H_GUEST_CACHELESS_SOURCE_LOCKED_SYSCALL_BATCH_FEX_ALIGN_FIX"',
      '"07H_GUEST_STACK_OPENAT_PATH_WITNESS_WITH_FEX_ALIGN_FIX"')
s=one(s,'"07H_FEX_ALIGN_SAFE_DIAGNOSTIC_BATCH_32"',
      '"07H_R3D16_GUEST_STACK_OPENAT_PATH_BATCH_32"')
s=one(s,'        report.put("batch_stop_marker",stop);',
'''        report.put("batch_stop_marker",stop);
        if(stop.equals("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS")) {
            String decoded=decodeR3D16PathChunks(phases);
            if(decoded==null) return "BATCH_REJECTED_GUEST_PATH_FRAGMENTS";
            report.put("batch_next_openat_guest_path",decoded);
            report.put("batch_next_openat_path_is_stack_readonly_witness",true);
            report.put("batch_next_openat_was_executed",false);
            report.put("batch_next_openat_requires_vfs_mapping",true);
        }''')
s=one(s,'        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))',
'''        if(stop.equals("E_BATCH_GUEST_PATH_CAPTURED_NEEDS_VFS"))
            return "BATCH_HALTED_PATH_CAPTURED_BEFORE_VFS";
        if(stop.equals("E_BATCH_GUEST_STACK_PATH_UNREADABLE"))
            return "BATCH_HALTED_SAFE_GUEST_PATH_READ_DENIED";
        if(stop.startsWith("E_BATCH_UNSUPPORTED_NR_"))''')
helper=r'''
    private static String decodeR3D16PathChunks(JSONArray phases) {
        final String head="N23_STACK_PATH_HEX_";
        String[] parts=new String[8];
        int claimedLength=-1;
        for(int i=0;i<phases.length();++i){
            String line=phases.optString(i,"");
            if(line.startsWith("N23_STACK_PATH_LENGTH_")){
                try{claimedLength=Integer.parseInt(line.substring(
                    "N23_STACK_PATH_LENGTH_".length()));}
                catch(NumberFormatException e){return null;}
            }
            if(!line.startsWith(head))continue;
            String rest=line.substring(head.length());
            if(rest.length()<4 || rest.charAt(2)!='_')return null;
            int idx;
            try{idx=Integer.parseInt(rest.substring(0,2));}
            catch(NumberFormatException e){return null;}
            if(idx<0 || idx>=parts.length || parts[idx]!=null)return null;
            String hex=rest.substring(3);
            if(hex.isEmpty() || hex.length()>64 || (hex.length()&1)!=0 ||
               !hex.matches("[0-9A-F]+"))return null;
            parts[idx]=hex;
        }
        if(claimedLength<1 || claimedLength>255)return null;
        StringBuilder result=new StringBuilder();
        for(String part:parts){
            if(part==null)break;
            for(int j=0;j<part.length();j+=2){
                int c=Integer.parseInt(part.substring(j,j+2),16);
                if(c<32 || c>126)return null;
                result.append((char)c);
            }
        }
        if(result.length()!=claimedLength)return null;
        return result.toString();
    }
'''
s=one(s,'    private static String inspectBatchJournal(',
       helper+'\n    private static String inspectBatchJournal(')
assert 'BATCH_HALTED_PATH_CAPTURED_BEFORE_VFS' in s
activity.write_text(s)
print('R3D16_READONLY_STACK_PATH_WITNESS_SOURCE_PROMOTION_PASS')
print('R3D16_UNKNOWN_GUEST_SYSCALLS_FAIL_CLOSED_AND_07D_07G_PRESERVED')
