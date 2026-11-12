cmake_minimum_required(VERSION 3.18.1)
project(fh5_native_port_p0 LANGUAGES C)
add_library(fh5_renderer SHARED vulkan_render.c)
target_compile_features(fh5_renderer PRIVATE c_std_11)
target_compile_options(fh5_renderer PRIVATE -Wall -Wextra)
target_link_libraries(fh5_renderer PRIVATE vulkan android)

# P2: A true bounded PE64 x86->AArch64 W^X instruction execution smoke test.
# This is NOT FEXCore, Wine, Win32, D3D12 or a Forza game-code runtime.
add_library(fh5_x64_micro SHARED pe64_micro_core.c pe64_micro_jni.c)
target_compile_features(fh5_x64_micro PRIVATE c_std_11)
target_compile_options(fh5_x64_micro PRIVATE -Wall -Wextra)

# P2.5: full x86-64 *instruction disassembly* in the APK (not CPU emulation).
# Capstone 5.0.9 stable, pinned to the signed release commit after security fixes.
include(FetchContent)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    fh5_capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 022575848782a4801fd150fdbc927effcbca0864
    GIT_SHALLOW FALSE
    GIT_PROGRESS FALSE
)
FetchContent_MakeAvailable(fh5_capstone)
set_property(TARGET capstone PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(fh5_x64_disasm SHARED x86_disasm_jni.c)
target_compile_features(fh5_x64_disasm PRIVATE c_std_11)
target_compile_options(fh5_x64_disasm PRIVATE -Wall -Wextra)
target_link_libraries(fh5_x64_disasm PRIVATE capstone_static)
