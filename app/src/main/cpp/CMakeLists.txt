cmake_minimum_required(VERSION 3.18.1)
project(rm11_vulkan_probe LANGUAGES C)
add_library(rm11_vulkan_probe SHARED vulkan_probe.c)
target_compile_features(rm11_vulkan_probe PRIVATE c_std_11)
target_compile_options(rm11_vulkan_probe PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_vulkan_probe PRIVATE vulkan)


add_library(rm11_vulkan_render SHARED vulkan_render.c)
target_compile_features(rm11_vulkan_render PRIVATE c_std_11)
target_compile_options(rm11_vulkan_render PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_vulkan_render PRIVATE vulkan android)


add_library(rm11_vulkan_suite SHARED vulkan_suite.c)
target_compile_features(rm11_vulkan_suite PRIVATE c_std_11)
target_compile_options(rm11_vulkan_suite PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_vulkan_suite PRIVATE vulkan android)

# Ships a real ARM64 execution/JIT host in the APK native library directory.
add_library(rm11_runtime_bootstrap SHARED runtime_bootstrap.c)
target_compile_features(rm11_runtime_bootstrap PRIVATE c_std_11)
target_compile_options(rm11_runtime_bootstrap PRIVATE -Wall -Wextra -Werror)

# Minimal PE32+ test: real bounded AMD64 instruction translation into ARM64.
# FEXCore/Wine/DirectX are not included in this educational native target.
add_library(rm11_pe64_micro SHARED pe64_micro_core.c pe64_micro_jni.c)
target_compile_features(rm11_pe64_micro PRIVATE c_std_11)
target_compile_options(rm11_pe64_micro PRIVATE -Wall -Wextra -Werror)
