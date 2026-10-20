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
