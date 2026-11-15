#include "carxpc/r3d32/native/preflight16_guest_mmap_pages.hpp"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>
int main(){
 std::vector<std::string> log;
 const auto s=carx_r3d32::run_preflight16(
   [&](const char* marker){log.emplace_back(marker);});
 assert(s.total==16&&s.passed==16&&s.failed==0&&s.ready());
 assert(log.size()==17);
 for(unsigned i=0;i<16;++i){
   assert(log[i].find("N49_R3D32_PREFLIGHT_MMAP_PAGE_CASE_")==0);
 }
 assert(log.back()=="N49_MMAP_PAGE_PREFLIGHT_TOTAL_16_PASS_16_FAIL_0");
 std::puts("R3D32_ALL_16_NESTED_FIXED_RWX_PARTIAL_MPROTECT_GUEST_MMAP_TESTS_PASS");
}
