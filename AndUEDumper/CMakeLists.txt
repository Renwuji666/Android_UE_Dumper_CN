cmake_minimum_required(VERSION 3.10)
set(NDK_PATH E:/ndk/android-ndk-r29)
set(CMAKE_TOOLCHAIN_FILE ${NDK_PATH}/build/cmake/android.toolchain.cmake)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_SYSTEM_VERSION 30)
set(ANDROID_PLATFORM 30)
set(ANDROID_ABI arm64-v8a)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/${ANDROID_ABI})
project(UEDump3r_${ANDROID_ABI})
project(shared_UEDump3r_${ANDROID_ABI})

set(KITTYMEMORY_PATH ../deps/KittyMemoryEx/KittyMemoryEx)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)

set(DEPS_PATH ../deps)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0 -g -std=c++20 -fexceptions -DDEBUG -DkNO_KEYSTONE -w")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O2 -s -std=c++20 -fexceptions -DNDEBUG -DkNO_KEYSTONE -w")

file(GLOB UE_SRC src/UE/*.cpp)

include_directories(${DEPS_PATH} ${KITTYMEMORY_PATH})
link_libraries(-llog)

add_executable(UEDump3r_${CMAKE_ANDROID_ARCH} ${UE_SRC} src/executable.cpp src/Dumper.cpp src/UPackageGenerator.cpp ${KITTYMEMORY_SRC} ${DEPS_PATH}/fmt/format.cc
        src/Utils/BufferFmt.cpp
        src/Utils/KittyCmdln.cpp
        src/Utils/ProgressUtils.cpp)
add_library(shared_UEDump3r_${CMAKE_ANDROID_ARCH} SHARED ${UE_SRC} src/library.cpp src/Dumper.cpp src/UPackageGenerator.cpp ${KITTYMEMORY_SRC} ${DEPS_PATH}/fmt/format.cc
        src/Utils/BufferFmt.cpp
        src/Utils/KittyCmdln.cpp
        src/Utils/ProgressUtils.cpp)

target_compile_definitions(UEDump3r_${CMAKE_ANDROID_ARCH} PRIVATE kEXECUTABLE)