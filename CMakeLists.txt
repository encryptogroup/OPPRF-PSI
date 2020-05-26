project(PSI_ANALYTICS)
cmake_minimum_required(VERSION 3.13)
cmake_policy(SET CMP0077 NEW)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

option(PSI_ANALYTICS_BUILD_TESTS "Build PSI analytics tests" ON)
option(PSI_ANALYTICS_BUILD_EXAMPLE "Build PSI analytics example" ON)

set(PSI_ANALYTICS_SOURCE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(PSI_ANALYTICS_BINARY_ROOT "${CMAKE_CURRENT_BINARY_DIR}")

set(Boost_USE_STATIC_LIBS OFF CACHE BOOL "Use shared boost libraries" FORCE)
set(Boost_USE_STATIC_RUNTIME OFF CACHE BOOL "Use shared boost runtime" FORCE)

find_package(Boost COMPONENTS system filesystem REQUIRED)
find_package(Threads REQUIRED)

set(ENABLE_RELIC ON CACHE BOOL "Build relic by default" FORCE)
set(MULTI PTHREAD CACHE STRING "Build relic with multithreading from pthread" FORCE)
find_package(RELIC QUIET)
if (RELIC_FOUND)
    message(STATUS "Found RELIC")
elseif (NOT RELIC_FOUND)
    message("RELIC was not found: add RELIC subdirectory")
        if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/relic/CMakeLists.txt")
            find_package(Git REQUIRED)
            message("initialize Git submodule: extern/relic")
            execute_process(COMMAND git submodule update --init extern/RELIC
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/relic)

    set(RLC_LIBRARY "${PSI_ANALYTICS_BINARY_ROOT}/extern/relic/lib/librelic_s.a")

    add_library(Relic STATIC IMPORTED)
    
    set_target_properties(Relic PROPERTIES
        IMPORTED_LOCATION ${RLC_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES "${PSI_ANALYTICS_BINARY_ROOT}/include;"
    )
    message("My relic path: ${PROJECT_SOURCE_DIR}/extern/relic/include/relic.h")
    
    file(COPY "${PROJECT_SOURCE_DIR}/extern/relic/include/" "${PSI_ANALYTICS_BINARY_ROOT}/extern/relic/include/relic_conf.h"
        DESTINATION "${PROJECT_BINARY_DIR}/include/relic"
    )
    
    
    

    target_link_libraries(Relic INTERFACE relic_s)
endif ()

find_package(ABY QUIET)
set(ENCRYPTO_UTILS_BUILD_TESTS OFF CACHE BOOL "Disable tests for the ENCRYPTO utils library" FORCE)
if (ABY_FOUND)
    message(STATUS "Found ABY")
elseif (NOT ABY_FOUND AND NOT TARGET ABY::aby)
    message("ABY was not found: add ABY subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ABY/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ABY")
        execute_process(COMMAND git submodule update --init extern/ABY
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/ABY)
endif ()

find_package(HashingTables QUIET)
if (HashingTables_FOUND)
    message(STATUS "Found HashingTables")
elseif (NOT HashingTables_FOUND AND NOT TARGET HashingTables::hashingtables)
    message("HashingTables was not found: add HashingTables subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/HashingTables/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/HashingTables")
        execute_process(COMMAND git submodule update --init extern/HashingTables
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/HashingTables)
endif ()

# we need to set these compile flags globally to compile compile libOTe and its dependencies
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -no-pie -pthread -maes -msse2 -msse3 -msse4.1 -mpclmul -mavx -mavx2")

set(ENABLE_SIMPLESTOT ON CACHE BOOL "Enable Simplest OT for Base OTs" FORCE)
find_package(libOTe QUIET)
if (libOTe_FOUND)
    message(STATUS "Found libOTe")
elseif (NOT libOTe_FOUND AND NOT TARGET libOTe::libote)
    message("libOTe was not found: add libOTe subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libOTe/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/libOTe")
        execute_process(COMMAND git submodule update --init --recursive extern/libOTe
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/libOTe)
endif ()

add_subdirectory(psi_analytics_eurocrypt19)

if (PSI_ANALYTICS_BUILD_TESTS)
    add_subdirectory(test)
endif (PSI_ANALYTICS_BUILD_TESTS)
