#include <jni.h>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes=std::vector<uint8_t>;
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
uint32_t u32(const Bytes& b,size_t o){
    check(o<=b.size()&&b.size()-o>=4,"truncated material offset");
    return uint32_t(b[o])|(uint32_t(b[o+1])<<8)|(uint32_t(b[o+2])<<16)|(uint32_t(b[o+3])<<24);
}
bool tag(const Bytes& b,size_t o,const char* t) {
    return o<=b.size()&&b.size()-o>=4&&std::memcmp(b.data()+o,t,4)==0;
}
float f32(const Bytes& b,size_t o){
    check(o<=b.size()&&b.size()-o>=4,"truncated float");
    uint32_t v=u32(b,o);float f;
    std::memcpy(&f,&v,sizeof f);
    return f;
}
struct Segment {std::string type;size_t off,len;uint32_t version;};
std::string asciiRefs(const Bytes& b,size_t off,size_t len,
                      const std::string& suffix){
    std::ostringstream out;
    if(off>b.size()||len>b.size()-off)return "";
    int n=0;
    const size_t end=off+len;
    for(size_t i=off;i+7<end;++i){
        if(b[i]!='G'||std::memcmp(b.data()+i,"Game:\\",6)!=0)continue;
        size_t j=i;
        while(j<end && j<i+350 && b[j]>=32 && b[j]<=126)++j;
        std::string candidate(reinterpret_cast<const char*>(b.data()+i),j-i);
        auto pos=candidate.find(suffix);
        if(pos!=std::string::npos && ++n<=8){
            candidate.resize(pos+suffix.size());
            if(candidate.find("..")==std::string::npos)
                out<<"   "<<candidate<<"\n";
            i+=candidate.size()-1;
        }
    }
    return out.str();
}
std::string audit(const Bytes& b,const std::string& filename){
    check(b.size()>=92&&b.size()<=1024*1024,"bad materialbin byte length");
    check(tag(b,0,"burG"),"Grub magic missing");
    check(u32(b,4)==257,"unknown Grub version");
    check(u32(b,12)==b.size(),"Grub file size mismatch");
    uint32_t count=u32(b,16);
    check(count==3,"expected MATL/MTUD/MTPR block count");
    check(size_t(20)+size_t(count)*24<=b.size(),"truncated Grub descriptors");
    Segment matl{}, mtud{}, mtpr{};
    int found=0;
    for(uint32_t i=0;i<count;++i){
        size_t p=20+size_t(i)*24;
        std::string kind(reinterpret_cast<const char*>(b.data()+p),4);
        uint32_t version=u32(b,p+4),off=u32(b,p+12),len=u32(b,p+16),expand=u32(b,p+20);
        check(off<=b.size() && len<=b.size()-off,"Grub segment outside file");
        check(len==expand,"unsupported compressed Grub segment");
        Segment x{kind,off,len,version};
        if(kind=="LTAM"){check(matl.type.empty(),"duplicate MATL");matl=x;found++;}
        else if(kind=="DUTM"){check(mtud.type.empty(),"duplicate MTUD");mtud=x;found++;}
        else if(kind=="RPTM"){check(mtpr.type.empty(),"duplicate MTPR");mtpr=x;found++;}
        else throw std::runtime_error("unknown Grub material tag");
    }
    check(found==3,"missing material segments");
    check(matl.version==197121 && mtpr.version==2,"material variant mismatch");
    const std::string header="M25 source material metadata";
    std::ostringstream result;
    result<<header<<"\n"<<"File: "<<filename<<" ("<<b.size()<<" bytes)\n";
    result<<"Grub: MATL "<<matl.len<<"B, MTUD "<<mtud.len<<"B, MTPR "<<mtpr.len<<"B\n";
    result<<"MTPR first byte / observed record count: "<<unsigned(b[mtpr.off])<<"\n";
    std::string shaders=asciiRefs(b,matl.off,matl.len,".shaderbin");
    std::string textures=asciiRefs(b,mtpr.off,mtpr.len,".swatchbin");
    result<<"Shader refs:\n"<<(shaders.empty()?"   (none found in ASCII path scan)\n":shaders);
    result<<"Swatch refs:\n"<<(textures.empty()?"   (none found in ASCII path scan)\n":textures);
    // Known M10 byte-layout observation only; this is NOT an identified shader property.
    const bool glass=filename=="Clear_Glass.materialbin" ||
                     filename=="colour_glass.materialbin" ||
                     filename=="dark_glass.materialbin";
    const bool paint=filename=="trafficCarpaint.materialbin";
    if(glass||paint){
        const size_t off=mtpr.off+(glass?29u:25u);
        check(off>=mtpr.off&&off+16<=mtpr.off+mtpr.len,"candidate vector missing");
        if(glass) check(b[mtpr.off+1]==3&&b[mtpr.off+2]==1&&
                        b[mtpr.off+3]==0xbf,"glass variant mismatch");
        if(paint) check(b[mtpr.off]==2&&b[mtpr.off+1]==3&&
                        b[mtpr.off+2]==1&&b[mtpr.off+3]==0x20,
                        "paint variant mismatch");
        float v[4]{};
        for(int i=0;i<4;++i){
            v[i]=f32(b,off+i*4);
            check(std::isfinite(v[i]) && v[i]>=0 && v[i]<=1.00001f,
                  "candidate vector outside [0..1]");
        }
        result<<std::fixed<<std::setprecision(6);
        result<<"Observed float4 at MTPR+"<<(off-mtpr.off)
              <<" (SEMANTICS UNVERIFIED): "
              <<v[0]<<", "<<v[1]<<", "<<v[2]<<", "<<v[3]<<"\n";
    } else {
        result<<"Float4 inference: intentionally not attempted on this variant.\n";
    }
    result<<"RESULT: PASS — structural metadata scan only; not original shader rendering.\n";
    return result.str();
}
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_r4_fh5probe_MainActivity_nativeAuditMaterial(JNIEnv* env,jclass,
                                                      jbyteArray array,jstring jname) {
    try {
        check(array&&jname,"missing material input");
        const jsize n=env->GetArrayLength(array);
        check(n>=92&&n<=1024*1024,"material size outside limit");
        Bytes bytes(static_cast<size_t>(n));
        env->GetByteArrayRegion(array,0,n,reinterpret_cast<jbyte*>(bytes.data()));
        if(env->ExceptionCheck())return nullptr;
        const char* chars=env->GetStringUTFChars(jname,nullptr);
        if(!chars)return nullptr;
        std::string filename(chars);
        env->ReleaseStringUTFChars(jname,chars);
        check(filename.size()>=12 && filename.size()<=128,"invalid filename");
        return env->NewStringUTF(audit(bytes,filename).c_str());
    }catch(const std::exception& ex){
        std::string message=std::string("FAIL: ")+ex.what();
        return env->NewStringUTF(message.c_str());
    }
}
