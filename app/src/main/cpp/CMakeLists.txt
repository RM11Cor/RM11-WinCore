cmake_minimum_required(VERSION 3.22.1)
project(rm11probe LANGUAGES CXX)

add_library(rm11probe SHARED VulkanProbe.cpp RuntimeNativeBridge.cpp)
target_compile_features(rm11probe PRIVATE cxx_std_17)
find_library(vulkan_lib vulkan REQUIRED)
target_link_libraries(rm11probe PRIVATE ${vulkan_lib} dl)

# Independently packaged .so used for a real in-APK dlopen/dlsym handshake.
# This is a diagnostics-only module, not an emulation engine.
add_library(rm11runtime_adapter SHARED RuntimePluginAdapter.cpp)
target_compile_features(rm11runtime_adapter PRIVATE cxx_std_17)
