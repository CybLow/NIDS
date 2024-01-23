cmake_minimum_required(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

project(NIDS)

set(CMAKE_CXX_STANDARD ${CMAKE_LANGUAGE_VERSION})
include(FindPCAP.cmake)

find_package(frugally-deep CONFIG REQUIRED)

add_executable(NIDS
        src/main.cpp
        src/packet/PacketCapture.cpp
        include/packet/PacketCapture.h
        src/packet/PacketInfo.cpp
        include/packet/PacketInfo.h
        src/utils/ListNetworkInterfaces.cpp
        include/utils/ListNetworkInterfaces.h
        src/ui/ui.cpp
        include/ui/ui.h
        src/packet/PacketCaptureNotifier.cpp
        include/packet/PacketCaptureNotifier.h
        src/ui/FullListDialog.cpp
        include/ui/FullListDialog.h
        src/packet/PacketFilter.cpp
        include/packet/PacketFilter.h
        src/packet/packetToCsv.cpp
        include/packet/packetToCsv.h
        src/packet/packetToCsv.cpp
        include/packet/packetToCsv.h
        include/packet/PacketFilter.h
        src/ui/HexAsciiDisplay.cpp
        include/ui/HexAsciiDisplay.h)

target_link_libraries(NIDS ${PCAP_LIBRARY})


find_package(Threads REQUIRED)
target_link_libraries(NIDS ${CMAKE_THREAD_LIBS_INIT})

set(CMAKE_INCLUDE_CURRENT_DIR ON)
find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
set(CMAKE_AUTOMOC ON)
target_link_libraries(NIDS Qt5::Widgets Qt5::Core Qt5::Gui frugally-deep::fdeep)