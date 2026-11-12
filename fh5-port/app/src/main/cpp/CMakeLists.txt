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
