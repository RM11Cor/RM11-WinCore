#include "carxpc/r3d31/native/batch64_syscall_preflight.hpp"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>
int main(){
 std::vector<std::string> results;
 const auto r=carx_r3d31::run_preflight_24(
     [&](const char* text){results.emplace_back(text);});
 assert(r.total==24&&r.passed==24&&r.failed==0&&r.ready());
 assert(results.size()==25);
 for(unsigned k=0;k<24;++k)
   assert(results[k].find("_CASE_")!=std::string::npos);
 assert(results.back()=="N45_PREFLIGHT24_SUMMARY_TOTAL_24_PASS_24_FAIL_0");
 std::puts("R3D31_24_MISC_ABI_PREFLIGHT_ADDED_TO_40_ROOTFS_CASES_PASS");
}
