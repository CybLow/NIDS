cmake_minimum_required(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
project(NIDS)

set(CMAKE_CXX_STANDARD ${CMAKE_LANGUAGE_VERSION})
include(FindPCAP.cmake)

add_executable(NIDS
        src/main.cpp
        src/utils/NetworkInterfaceSelector.cpp
        include/utils/NetworkInterfaceSelector.h
        src/packet/PacketCapture.cpp
        include/packet/PacketCapture.h
        src/packet/PacketProcessor.cpp
        include/packet/PacketProcessor.h
        src/packet/PacketInfo.cpp
        include/packet/PacketInfo.h
        include/packet/PacketType.h
        src/packet/PacketType.cpp
        src/utils/Buffer.cpp
        include/utils/Buffer.h)
target_link_libraries(NIDS ${PCAP_LIBRARY})

find_package(Threads REQUIRED)
target_link_libraries(NIDS ${CMAKE_THREAD_LIBS_INIT})

find_library(NDPI_LIBRARY NAMES ndpi)
target_link_libraries(NIDS ${NDPI_LIBRARY})