cmake_minimum_required(VERSION 3.16)
project(someip_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

set(AGENT_SOURCES
    src/main.cpp
    src/someip/someip_dissector.cpp
    src/capture/pcap_backend.cpp
    src/capture/qnx_bpf_backend.cpp
    src/capture/linux_raw_backend.cpp
)

add_executable(someip_agent ${AGENT_SOURCES})
target_include_directories(someip_agent PRIVATE include)
target_compile_options(someip_agent PRIVATE -Wall -Wextra -Wpedantic)

# Platform-specific configurations
if(CMAKE_SYSTEM_NAME STREQUAL "QNX" OR DEFINED QNX_TARGET)
    message(STATUS "Targeting QNX Neutrino RTOS")
    target_compile_definitions(someip_agent PRIVATE __QNX__=1 __QNXNTO__=1 HAVE_QNX_BPF=1)

    # QNX requires libsocket for networking
    find_library(SOCKET_LIBRARY NAMES socket)
    if(SOCKET_LIBRARY)
        message(STATUS "Found QNX socket library: ${SOCKET_LIBRARY}")
        target_link_libraries(someip_agent PRIVATE ${SOCKET_LIBRARY})
    else()
        message(WARNING "QNX socket library not found directly by CMake; linking -lsocket")
        target_link_libraries(someip_agent PRIVATE socket)
    endif()

    # Check if libpcap is available in QNX SDP
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        message(STATUS "Found libpcap for QNX: ${PCAP_LIBRARY}")
        target_compile_definitions(someip_agent PRIVATE HAVE_PCAP=1)
        target_include_directories(someip_agent PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(someip_agent PRIVATE ${PCAP_LIBRARY})
    else()
        message(STATUS "libpcap not found on QNX. SBC Agent will use native QNX BPF (/dev/bpf) backend.")
    endif()

else()
    # Linux / Unix host or SBC
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        target_compile_definitions(someip_agent PRIVATE HAVE_PCAP=1)
        target_include_directories(someip_agent PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(someip_agent PRIVATE ${PCAP_LIBRARY})
    else()
        message(WARNING "libpcap not found. Capture will be disabled unless libpcap is installed.")
    endif()

    if(UNIX)
        target_link_libraries(someip_agent PRIVATE pthread)
    endif()
endif()

# Automated unit tests for SOME/IP and SOME/IP-SD dissector
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_dissector.cpp")
    add_executable(test_dissector
        tests/test_dissector.cpp
        src/someip/someip_dissector.cpp
    )
    target_include_directories(test_dissector PRIVATE include)
    target_compile_options(test_dissector PRIVATE -Wall -Wextra)
endif()
