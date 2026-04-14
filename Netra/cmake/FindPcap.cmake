include(FindPackageHandleStandardArgs)

set(_PCAP_ROOT_HINTS)

if(DEFINED PCAP_ROOT AND NOT PCAP_ROOT STREQUAL "")
    list(APPEND _PCAP_ROOT_HINTS "${PCAP_ROOT}")
endif()

set(_PCAP_ROOT_HINTS
    ${_PCAP_ROOT_HINTS}
    "$ENV{PCAP_ROOT}"
    "$ENV{NPCAP_DIR}"
    "$ENV{ProgramFiles}/Npcap SDK"
    "$ENV{ProgramW6432}/Npcap SDK"
    "C:/Program Files/Npcap SDK"
    "C:/Program Files (x86)/Npcap SDK"
)

if(WIN32)
    list(APPEND _PCAP_ROOT_HINTS
        "${CMAKE_CURRENT_LIST_DIR}/../third_party/NpcapSDK"
    )
endif()

set(_PCAP_INCLUDE_HINTS)
set(_PCAP_LIBRARY_HINTS)

list(REMOVE_DUPLICATES _PCAP_ROOT_HINTS)

foreach(_root IN LISTS _PCAP_ROOT_HINTS)
    if(_root)
        list(APPEND _PCAP_INCLUDE_HINTS
            "${_root}/Include"
            "${_root}/include"
        )
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            list(APPEND _PCAP_LIBRARY_HINTS
                "${_root}/Lib/x64"
                "${_root}/Lib"
                "${_root}/lib/x64"
                "${_root}/lib"
            )
        else()
            list(APPEND _PCAP_LIBRARY_HINTS
                "${_root}/Lib"
                "${_root}/Lib/x86"
                "${_root}/lib"
                "${_root}/lib/x86"
            )
        endif()
    endif()
endforeach()

find_path(Pcap_INCLUDE_DIR
    NAMES pcap.h
    HINTS ${_PCAP_INCLUDE_HINTS}
)

if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        find_library(Pcap_LIBRARY
            NAMES wpcap
            PATHS ${_PCAP_LIBRARY_HINTS}
            PATH_SUFFIXES x64
            NO_DEFAULT_PATH
        )
        find_library(Pcap_PACKET_LIBRARY
            NAMES Packet
            PATHS ${_PCAP_LIBRARY_HINTS}
            PATH_SUFFIXES x64
            NO_DEFAULT_PATH
        )
    endif()

    if(NOT Pcap_LIBRARY)
        find_library(Pcap_LIBRARY
            NAMES wpcap
            HINTS ${_PCAP_LIBRARY_HINTS}
        )
    endif()

    if(NOT Pcap_PACKET_LIBRARY)
        find_library(Pcap_PACKET_LIBRARY
            NAMES Packet
            HINTS ${_PCAP_LIBRARY_HINTS}
        )
    endif()
else()
    find_library(Pcap_LIBRARY
        NAMES pcap
        HINTS ${_PCAP_LIBRARY_HINTS}
    )
endif()

find_package_handle_standard_args(Pcap
    REQUIRED_VARS Pcap_INCLUDE_DIR Pcap_LIBRARY
)

if(Pcap_FOUND)
    set(Pcap_INCLUDE_DIRS "${Pcap_INCLUDE_DIR}")
    set(Pcap_LIBRARIES "${Pcap_LIBRARY}")

    if(NOT TARGET Pcap::Pcap)
        add_library(Pcap::Pcap UNKNOWN IMPORTED)
        set_target_properties(Pcap::Pcap PROPERTIES
            IMPORTED_LOCATION "${Pcap_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${Pcap_INCLUDE_DIR}"
        )

        if(WIN32 AND Pcap_PACKET_LIBRARY)
            set_property(TARGET Pcap::Pcap APPEND PROPERTY
                INTERFACE_LINK_LIBRARIES "${Pcap_PACKET_LIBRARY}"
            )
            list(APPEND Pcap_LIBRARIES "${Pcap_PACKET_LIBRARY}")
        endif()
    endif()
endif()

mark_as_advanced(Pcap_INCLUDE_DIR Pcap_LIBRARY Pcap_PACKET_LIBRARY)
