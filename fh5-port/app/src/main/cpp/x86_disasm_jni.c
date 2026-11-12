/*
 * FH5 P2.6: Capstone bounded original x86-64 entrypoint control flow gate.
 * No game bytes are exported, no game code executed, no runtime initialized.
 */
#include "x86_cf_core.h"
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static jstring jstr(JNIEnv *env,const char *s) {
    return (*env)->NewStringUTF(env,s);
}
static int append(char *out,size_t cap,size_t *used,const char *fmt,
                  const char *str) {
    if(*used>=cap)return 0;
    int count=snprintf(out+*used,cap-*used,fmt,str);
    if(count<0 || (size_t)count>=cap-*used)return 0;
    *used+=(size_t)count;
    return 1;
}
JNIEXPORT jstring JNICALL
Java_com_fh5_port_X86Disasm_nativeInspect(JNIEnv *env,jclass unused,
                    jbyteArray sample,jlong startRva,jlong sizeOfImage) {
    (void)unused;
    if(!sample)return jstr(env,
        "{\"status\":\"entry_missing\",\"original_game_executed\":false}");
    jsize n=(*env)->GetArrayLength(env,sample);
    if(n<1 || n>FH5_CF_SAMPLE_MAX || startRva<0 || sizeOfImage<=0)
        return jstr(env,
            "{\"status\":\"invalid_or_unbounded_input\",\"original_game_executed\":false}");
    uint8_t bytes[FH5_CF_SAMPLE_MAX];
    memset(bytes,0,sizeof(bytes));
    (*env)->GetByteArrayRegion(env,sample,0,n,(jbyte*)bytes);
    if((*env)->ExceptionCheck(env))return NULL;
    fh5_cf_result cf;
    int status=fh5_cf_analyze(bytes,(size_t)n,
                      (uint64_t)startRva,(uint64_t)sizeOfImage,&cf);
    memset(bytes,0,sizeof(bytes));
    if(status!=0)return jstr(env,
        "{\"status\":\"capstone_disassembly_failed\",\"original_game_executed\":false}");
    char out[3500];
    int nprinted=snprintf(out,sizeof(out),
       "{\"stage\":\"P2_6_CAPSTONE_ENTRY_CONTROL_FLOW_READ_ONLY\","
       "\"engine\":\"Capstone\",\"engine_version\":\"5.0.9\","
       "\"status\":\"decoded\",\"linear_decode_only\":true,"
       "\"control_flow_validated\":false,\"first_transfer_boundary_identified\":%s,"
       "\"decoded_instruction_count\":%zu,\"requested_sample_bytes\":%d,"
       "\"decoded_bytes\":%zu,\"instruction_mnemonics\":[",
       cf.transfer_found?"true":"false",cf.decoded_count,(int)n,cf.decoded_bytes);
    if(nprinted<0 || (size_t)nprinted>=sizeof(out))return jstr(env,
        "{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    size_t used=(size_t)nprinted;
    for(size_t i=0;i<cf.decoded_count;i++) {
        if(!append(out,sizeof(out),&used,
              i==0?"\"%s\"":",\"%s\"",cf.linear_mnemonics[i]))
            return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    }
    nprinted=snprintf(out+used,sizeof(out)-used,
       "],\"first_basic_block_instruction_count\":%zu,"
       "\"first_basic_block_bytes\":%zu,\"first_basic_block_mnemonics\":[",
       cf.first_block_count,cf.first_block_bytes);
    if(nprinted<0 || (size_t)nprinted>=sizeof(out)-used)
        return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    used+=(size_t)nprinted;
    for(size_t i=0;i<cf.first_block_count;i++) {
        if(!append(out,sizeof(out),&used,
                i==0?"\"%s\"":",\"%s\"",cf.first_block_mnemonics[i]))
            return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    }
    nprinted=snprintf(out+used,sizeof(out)-used,
       "],\"first_transfer_kind\":\"%s\","
       "\"first_transfer_target_kind\":\"%s\","
       "\"first_transfer_instruction_index\":%zu,"
       "\"first_transfer_offset_in_sample\":%zu,"
       "\"first_transfer_length\":%zu,"
       "\"first_transfer_target_within_exe_image\":%s,"
       "\"first_transfer_target_within_sample\":%s,"
       "\"first_transfer_target_rva\":",
       cf.transfer_kind,cf.target_kind,
       cf.transfer_found?cf.transfer_insn_index:0u,
       cf.transfer_found?cf.transfer_offset:0u,
       cf.transfer_found?cf.transfer_length:0u,
       cf.target_within_image?"true":"false",
       cf.target_within_sample?"true":"false");
    if(nprinted<0 || (size_t)nprinted>=sizeof(out)-used)
        return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    used+=(size_t)nprinted;
    if(cf.direct_target_valid)
        nprinted=snprintf(out+used,sizeof(out)-used,"%llu",
                  (unsigned long long)cf.direct_target_rva);
    else nprinted=snprintf(out+used,sizeof(out)-used,"null");
    if(nprinted<0 || (size_t)nprinted>=sizeof(out)-used)
        return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    used+=(size_t)nprinted;
    nprinted=snprintf(out+used,sizeof(out)-used,
       ",\"possible_branch_instructions\":%zu,"
       "\"possible_call_instructions\":%zu,\"possible_return_instructions\":%zu,"
       "\"instructions_with_memory_operands\":%zu,"
       "\"linear_tail_after_first_transfer_unverified\":true,"
       "\"original_game_executed\":false,\"executed\":false,"
       "\"raw_bytes_exported\":false,\"operands_exported\":false,"
       "\"game_playable\":false}",
       cf.branch_count,cf.call_count,cf.return_count,cf.memory_operand_count);
    if(nprinted<0 || (size_t)nprinted>=sizeof(out)-used)
        return jstr(env,"{\"status\":\"report_overflow\",\"original_game_executed\":false}");
    return jstr(env,out);
}
