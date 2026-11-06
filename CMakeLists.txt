cmake_minimum_required(VERSION 3.12)
project(privacy_scanner LANGUAGES CXX)

add_executable(privacy-scanner src/main.cpp)
target_compile_features(privacy-scanner PRIVATE cxx_std_17)
set_target_properties(privacy-scanner PROPERTIES CXX_EXTENSIONS OFF)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(privacy-scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()
