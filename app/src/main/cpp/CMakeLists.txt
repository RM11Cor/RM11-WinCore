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

# Dedicated read-only NLS redirect for the APK-hosted native Wine ntdll.
add_library(rm11_wine_data_redirect SHARED wine_data_redirect.c)
target_compile_features(rm11_wine_data_redirect PRIVATE c_std_11)
target_compile_options(rm11_wine_data_redirect PRIVATE -Wall -Wextra -Werror)

# v3.0.2 app-host-only FreeType diagnostics, never preloaded in Wine/wineserver.
add_library(rm11_wine_font_probe SHARED wine_native_font_probe.c)
target_compile_features(rm11_wine_font_probe PRIVATE c_std_11)
target_compile_options(rm11_wine_font_probe PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_wine_font_probe PRIVATE dl)

# v4.0.65 opt-in native abort caller evidence for selected Windows games only.
# Loaded as a *separate* LD_PRELOAD before the unchanged Wine shims;
# no changes to wineserver or normal Nova desktop sessions.
add_library(rm11_abort_caller_v465 SHARED rm11_abort_caller_v465.c)
target_compile_features(rm11_abort_caller_v465 PRIVATE c_std_11)
target_compile_options(rm11_abort_caller_v465 PRIVATE
    -Wall -Wextra -Werror -fno-omit-frame-pointer)
target_link_libraries(rm11_abort_caller_v465 PRIVATE dl)


# v4.90.1 isolated signed Turnip ICD enumeration; Android's vendor Vulkan
# loader is NOT linked, and no global Vulkan environment is modified.
add_library(rm11_turnip_icd_probe SHARED rm11_turnip_icd_probe.c)
target_compile_features(rm11_turnip_icd_probe PRIVATE c_std_11)
target_compile_options(rm11_turnip_icd_probe PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_turnip_icd_probe PRIVATE dl)


# v4.90.3 private ICD: actual graphics queue buffer fill and CPU readback.
# This diagnostic is isolated; it does NOT prove Android display frames.
add_library(rm11_turnip_gpu_submit SHARED rm11_turnip_gpu_submit.c)
target_compile_features(rm11_turnip_gpu_submit PRIVATE c_std_11)
target_compile_options(rm11_turnip_gpu_submit PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_turnip_gpu_submit PRIVATE dl)


# v4.90.4 separate-process private signed Turnip Android WSI experiment.
# NO linkage to the system Vulkan loader; fail when ICD lacks Android WSI.
add_library(rm11_private_turnip_surface SHARED rm11_private_turnip_surface.c)
target_compile_features(rm11_private_turnip_surface PRIVATE c_std_11)
target_compile_options(rm11_private_turnip_surface PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_private_turnip_surface PRIVATE dl android)


# v4.90.93 isolate private Termux desktop Vulkan loader and signed Freedreno ICD.
# Tests X11 instance extensions and creates an instance, never claims present.
add_library(rm11_private_x11_loader_probe_v49093 SHARED
    rm11_private_x11_loader_probe_v49093.c)
target_compile_features(rm11_private_x11_loader_probe_v49093 PRIVATE c_std_11)
target_compile_options(rm11_private_x11_loader_probe_v49093 PRIVATE
    -Wall -Wextra -Werror)
target_link_libraries(rm11_private_x11_loader_probe_v49093 PRIVATE dl)

# v4.90.5 private Turnip GPU-written color -> CPU NativeWindow experiment.
# Android window is posted via libandroid, never via system Vulkan. This
# explicitly does NOT assert direct Vulkan WSI/Swapchain support or Wine frames.
add_library(rm11_turnip_buffer_surface SHARED rm11_turnip_buffer_surface.c)
target_compile_features(rm11_turnip_buffer_surface PRIVATE c_std_11)
target_compile_options(rm11_turnip_buffer_surface PRIVATE -Wall -Wextra -Werror)
target_link_libraries(rm11_turnip_buffer_surface PRIVATE dl android)
