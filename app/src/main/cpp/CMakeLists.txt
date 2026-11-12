cmake_minimum_required(VERSION 3.22.1)
project(carx_native_probe LANGUAGES CXX)
add_library(carx_native_probe SHARED
    carx_native_vulkan_probe.cpp
    carx_native_gpu_clear_probe.cpp)
target_compile_features(carx_native_probe PRIVATE cxx_std_17)
target_compile_options(carx_native_probe PRIVATE -Wall -Wextra -Werror)
target_link_libraries(carx_native_probe PRIVATE vulkan log)
