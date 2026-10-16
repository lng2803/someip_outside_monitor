# CMake Toolchain File for QNX Neutrino RTOS (7.0, 7.1, 8.0)
#
# Usage:
#   source $QNX_DIR/qnxsdp-env.sh
#   cmake -S . -B build_qnx -DCMAKE_TOOLCHAIN_FILE=cmake/qnx_nto_toolchain.cmake -DQNX_ARCH=aarch64
#   cmake --build build_qnx -j

set(CMAKE_SYSTEM_NAME QNX)
set(CMAKE_SYSTEM_VERSION 8.0)

if(NOT DEFINED QNX_ARCH)
    set(QNX_ARCH "aarch64")
endif()

if(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})
    message(FATAL_ERROR "QNX_HOST or QNX_TARGET environment variables not set. Please run 'source qnxsdp-env.sh' from your QNX SDP directory.")
endif()

set(QNX_HOST "$ENV{QNX_HOST}")
set(QNX_TARGET "$ENV{QNX_TARGET}")

if(QNX_ARCH STREQUAL "aarch64" OR QNX_ARCH STREQUAL "aarch64le")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(QNX_PROCESSOR "nto-aarch64-le")
    set(COMPILER_PREFIX "ntoaarch64-")
elseif(QNX_ARCH STREQUAL "x86_64")
    set(CMAKE_SYSTEM_PROCESSOR x86_64)
    set(QNX_PROCESSOR "nto-x86_64")
    set(COMPILER_PREFIX "ntox86_64-")
elseif(QNX_ARCH STREQUAL "armv7" OR QNX_ARCH STREQUAL "armv7le")
    set(CMAKE_SYSTEM_PROCESSOR armv7)
    set(QNX_PROCESSOR "nto-armv7-le")
    set(COMPILER_PREFIX "ntoarmv7-")
else()
    message(FATAL_ERROR "Unsupported QNX_ARCH: ${QNX_ARCH}")
endif()

set(CMAKE_C_COMPILER "${QNX_HOST}/usr/bin/qcc")
set(CMAKE_CXX_COMPILER "${QNX_HOST}/usr/bin/q++")

set(CMAKE_C_FLAGS_INIT "-Vgcc_${QNX_PROCESSOR}")
set(CMAKE_CXX_FLAGS_INIT "-Vgcc_${QNX_PROCESSOR} -Y_cxx")

set(CMAKE_FIND_ROOT_PATH "${QNX_TARGET}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
