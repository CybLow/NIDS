# FindPCAP.cmake
# Cross-platform PCAP library finder (libpcap on Linux/macOS, Npcap/WinPcap on Windows)
#
# This module defines:
#   PCAP_FOUND        - True if PCAP was found
#   PCAP_LIBRARY      - The PCAP library to link against
#   PCAP_INCLUDE_DIR  - The include directory for pcap headers
#   PCAP::PCAP        - Imported target

if(WIN32)
    # Npcap SDK default install locations
    set(_PCAP_HINTS
        "$ENV{NPCAP_SDK}"
        "C:/npcap-sdk"
        "C:/Program Files/Npcap/SDK"
        "C:/Program Files (x86)/Npcap/SDK"
    )

    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS ${_PCAP_HINTS}
        PATH_SUFFIXES Include include
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_PCAP_LIB_SUFFIX "Lib/x64")
    else()
        set(_PCAP_LIB_SUFFIX "Lib")
    endif()

    find_library(PCAP_LIBRARY
        NAMES wpcap
        HINTS ${_PCAP_HINTS}
        PATH_SUFFIXES ${_PCAP_LIB_SUFFIX}
    )

    find_library(PCAP_PACKET_LIBRARY
        NAMES Packet
        HINTS ${_PCAP_HINTS}
        PATH_SUFFIXES ${_PCAP_LIB_SUFFIX}
    )
else()
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG PCAP_LIBRARY PCAP_INCLUDE_DIR)

if(PCAP_FOUND AND NOT TARGET PCAP::PCAP)
    add_library(PCAP::PCAP UNKNOWN IMPORTED)
    set_target_properties(PCAP::PCAP PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
    if(WIN32 AND PCAP_PACKET_LIBRARY)
        set_property(TARGET PCAP::PCAP APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES "${PCAP_PACKET_LIBRARY}" ws2_32)
    endif()
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY PCAP_PACKET_LIBRARY)
