/*
 * FH5 P2.5: bounded original x86-64 linear disassembly inside Android APK.
 * Capstone 5.0.9, commit 022575848782a4801fd150fdbc927effcbca0864.
 * READ-ONLY. No game code JIT, runtime launch, crypto bypass or game byte export.
 */
#include <capstone/capstone.h>
#include <jni.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_GAME_SAMPLE 512
#define MAX_LISTED_INSTRUCTIONS 16

static void safe_mnemonic(const char *in,char out[32]) {
    size_t k=0;
    if(!in) { out[0]='?';out[1]=0;return; }
    for(size_t i=0;in[i]!=0 && k<31;i++) {
        unsigned char c=(unsigned char)in[i];
        if((c>='a' && c<='z') || (c>='A' && c<='Z') ||
           (c>='0' && c<='9') || c=='_') out[k++]=(char)c;
    }
    if(k==0)out[k++]='?';
    out[k]=0;
}
static jstring result(JNIEnv *env,const char *text) {
    return (*env)->NewStringUTF(env,text);
}
JNIEXPORT jstring JNICALL
Java_com_fh5_port_X86Disasm_nativeInspect(JNIEnv *env,jclass cls,jbyteArray sample) {
    (void)cls;
    if(!sample) return result(env,
        "{\"status\":\"empty\",\"executed\":false,\"raw_bytes_exported\":false}");
    jsize n=(*env)->GetArrayLength(env,sample);
    if(n<1 || n>MAX_GAME_SAMPLE) return result(env,
        "{\"status\":\"sample_length_out_of_bounds\",\"executed\":false,\"raw_bytes_exported\":false}");
    uint8_t bytes[MAX_GAME_SAMPLE];
    (*env)->GetByteArrayRegion(env,sample,0,n,(jbyte*)bytes);
    if((*env)->ExceptionCheck(env))return NULL;

    csh handle=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK) {
        return result(env,
            "{\"status\":\"disassembler_init_failed\",\"executed\":false,\"raw_bytes_exported\":false}");
    }
    cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);
    cs_insn *inst=NULL;
    size_t count=cs_disasm(handle,bytes,(size_t)n,0,
                           MAX_LISTED_INSTRUCTIONS,&inst);
    size_t covered=0,mem=0,branches=0,call=0,ret=0;
    char output[3000];
    int len=snprintf(output,sizeof(output),
       "{\"stage\":\"P2_5_CAPSTONE_X86_64_READ_ONLY\","
       "\"engine\":\"Capstone\",\"engine_version\":\"5.0.9\","
       "\"status\":\"%s\",\"linear_decode_only\":true,"
       "\"control_flow_validated\":false,"
       "\"decoded_instruction_count\":%zu,\"requested_sample_bytes\":%d,"
       "\"instruction_mnemonics\":[",
       count>0?"decoded":"undecodable",(size_t)count,(int)n);
    if(len<0 || (size_t)len>=sizeof(output)) {
        if(inst) cs_free(inst,count);
        cs_close(&handle);
        return result(env,"{\"status\":\"report_overflow\",\"executed\":false}");
    }
    size_t used=(size_t)len;
    for(size_t i=0;i<count;i++) {
        char mnemonic[32];
        safe_mnemonic(inst[i].mnemonic,mnemonic);
        covered+=inst[i].size;
        if(cs_insn_group(handle,&inst[i],CS_GRP_JUMP))branches++;
        if(cs_insn_group(handle,&inst[i],CS_GRP_CALL))call++;
        if(cs_insn_group(handle,&inst[i],CS_GRP_RET))ret++;
        if(inst[i].detail) {
            cs_x86 *x=&inst[i].detail->x86;
            for(unsigned k=0;k<x->op_count;k++) {
                if(x->operands[k].type==X86_OP_MEM) {
                    mem++;break;
                }
            }
        }
        int nn=snprintf(output+used,sizeof(output)-used,
                         "%s\"%s\"",i?",":"",mnemonic);
        if(nn<0 || (size_t)nn>=sizeof(output)-used) {
            cs_free(inst,count);cs_close(&handle);
            return result(env,"{\"status\":\"report_overflow\",\"executed\":false}");
        }
        used+=(size_t)nn;
    }
    int nn=snprintf(output+used,sizeof(output)-used,
      "],\"decoded_bytes\":%zu,\"possible_branch_instructions\":%zu,"
      "\"possible_call_instructions\":%zu,\"possible_return_instructions\":%zu,"
      "\"instructions_with_memory_operands\":%zu,"
      "\"original_game_executed\":false,\"executed\":false,"
      "\"raw_bytes_exported\":false,\"operands_exported\":false,"
      "\"game_playable\":false}",
      covered,branches,call,ret,mem);
    if(nn<0 || (size_t)nn>=sizeof(output)-used) {
        if(inst) cs_free(inst,count);
        cs_close(&handle);
        return result(env,"{\"status\":\"report_overflow\",\"executed\":false}");
    }
    if(inst)cs_free(inst,count);
    cs_close(&handle);
    memset(bytes,0,sizeof(bytes));
    return result(env,output);
}
