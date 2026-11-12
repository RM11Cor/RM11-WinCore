/* Bounded x86-64 control-flow metadata analysis: never executes game code. */
#include "x86_cf_core.h"
#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>

static void safe_name(const char *value,char out[FH5_CF_MNEMONIC_MAX]) {
    size_t j=0;
    for(size_t i=0; value && value[i] && j+1<FH5_CF_MNEMONIC_MAX;i++) {
        unsigned char c=(unsigned char)value[i];
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
           (c>='0'&&c<='9')||c=='_') out[j++]=(char)c;
    }
    if(j==0)out[j++]='?';
    out[j]=0;
}
static int is_branch(csh h,const cs_insn *ins) {
    return cs_insn_group(h,ins,CS_GRP_JUMP)!=0;
}
static int is_call(csh h,const cs_insn *ins) {
    return cs_insn_group(h,ins,CS_GRP_CALL)!=0;
}
static int is_return(csh h,const cs_insn *ins) {
    return cs_insn_group(h,ins,CS_GRP_RET)!=0;
}

int fh5_cf_analyze(const uint8_t *sample,size_t n,
                   uint64_t rva,uint64_t image_size,fh5_cf_result *out) {
    if(!out)return -1;
    memset(out,0,sizeof(*out));
    strcpy(out->transfer_kind,"none");
    strcpy(out->target_kind,"none");
    if(!sample || n<1 || n>FH5_CF_SAMPLE_MAX || image_size<1 || rva>=image_size)
        return -2;
    csh handle=0;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK)return -3;
    if(cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK) {
        cs_close(&handle);return -4;
    }
    cs_insn *ins=NULL;
    size_t count=cs_disasm(handle,sample,n,rva,FH5_CF_MAX_INSNS,&ins);
    if(count==0){cs_close(&handle);return -5;}
    out->decode_ok=1;
    out->decoded_count=count;
    for(size_t i=0;i<count;i++) {
        const cs_insn *item=&ins[i];
        if(item->address < rva || item->size==0 || item->size>15 ||
           (uint64_t)item->size > (uint64_t)n-(item->address-rva)) {
            cs_free(ins,count);cs_close(&handle);memset(out,0,sizeof(*out));
            return -6;
        }
        size_t rel=(size_t)(item->address-rva);
        if(rel>n || item->size>n-rel) {
            cs_free(ins,count);cs_close(&handle);memset(out,0,sizeof(*out));
            return -6;
        }
        out->decoded_bytes=rel+item->size;
        safe_name(item->mnemonic,out->linear_mnemonics[i]);
        int branch=is_branch(handle,item),call=is_call(handle,item),ret=is_return(handle,item);
        if(branch)out->branch_count++;
        if(call)out->call_count++;
        if(ret)out->return_count++;
        if(item->detail) {
            const cs_x86 *details=&item->detail->x86;
            for(unsigned k=0;k<details->op_count;k++) {
                if(details->operands[k].type==X86_OP_MEM) {
                    out->memory_operand_count++;break;
                }
            }
        }
        if(!out->transfer_found) {
            safe_name(item->mnemonic,out->first_block_mnemonics[i]);
            out->first_block_count=i+1;
            out->first_block_bytes=out->decoded_bytes;
            if(branch||call||ret) {
                out->transfer_found=1;
                out->transfer_insn_index=i;
                out->transfer_offset=rel;
                out->transfer_length=item->size;
                if(call)strcpy(out->transfer_kind,"call");
                else if(ret)strcpy(out->transfer_kind,"return");
                else if(item->id==X86_INS_JMP)strcpy(out->transfer_kind,"unconditional_jump");
                else strcpy(out->transfer_kind,"conditional_jump");
                if(!ret && item->detail && item->detail->x86.op_count>0) {
                    const cs_x86_op *operand=&item->detail->x86.operands[0];
                    if(operand->type==X86_OP_IMM) {
                        strcpy(out->target_kind,"direct");
                        uint64_t target=(uint64_t)operand->imm;
                        /* Capstone's immediate is already the absolute target
                         * relative to the supplied RVA, not the rel32 delta. */
                        if(target<image_size) {
                            out->direct_target_valid=1;
                            out->direct_target_rva=target;
                            out->target_within_image=1;
                            out->target_within_sample=(target>=rva && target-rva<n);
                        } else strcpy(out->target_kind,"direct_outside_image");
                    } else if(operand->type==X86_OP_REG) {
                        strcpy(out->target_kind,"register_indirect");
                    } else if(operand->type==X86_OP_MEM) {
                        strcpy(out->target_kind,"memory_indirect");
                    } else strcpy(out->target_kind,"unresolved");
                }
            }
        }
    }
    cs_free(ins,count);
    cs_close(&handle);
    return 0;
}
