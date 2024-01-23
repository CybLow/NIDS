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
        include/utils/Buffer.h
        src/utils/ListNetworkInterfaces.cpp
        include/utils/ListNetworkInterfaces.h
        src/ui/ui.cpp
        include/ui/ui.h
        src/packet/PacketSignalEmitter.cpp
        include/packet/PacketSignalEmitter.h
        src/packet/PacketCaptureNotifier.cpp
        include/packet/PacketCaptureNotifier.h
        src/ui/FullListDialog.cpp
        include/ui/FullListDialog.h
        src/packet/PacketFilter.cpp
        include/packet/PacketFilter.h
        src/ui/HexAsciiDisplay.cpp
        include/ui/HexAsciiDisplay.h)
target_link_libraries(NIDS ${PCAP_LIBRARY})

find_package(Threads REQUIRED)
target_link_libraries(NIDS ${CMAKE_THREAD_LIBS_INIT})

set(CMAKE_INCLUDE_CURRENT_DIR ON)
find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
set(CMAKE_AUTOMOC ON)
target_link_libraries(NIDS Qt5::Widgets Qt5::Core Qt5::Gui)