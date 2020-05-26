find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

add_library(psi_analytics_eurocrypt19
        common/psi_analytics.cpp
        common/helpers.cpp
        polynomials/Mersenne.cpp
        polynomials/Poly.cpp
        ots/ots.cpp
        )
        
set_target_properties(psi_analytics_eurocrypt19
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(psi_analytics_eurocrypt19
        PRIVATE
        -march=native
        -ffunction-sections -mpclmul -mbmi2 -maes
        -mavx -msse2 -msse3 -msse4.1
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

target_link_libraries(psi_analytics_eurocrypt19 INTERFACE
        ABY::aby
        ENCRYPTO_utils::encrypto_utils
        ${GLIB_LDFLAGS}
        gmp
        gmpxx
        ntl
        HashingTables
        libOTe
        Boost::program_options
        Threads::Threads
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        )

target_include_directories(psi_analytics_eurocrypt19 PUBLIC
        ${PSI_ANALYTICS_SOURCE_ROOT}/psi_analytics_eurocrypt19
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/HashingTables
        ${GLIB_INCLUDE_DIRS}
        )

if (PSI_ANALYTICS_BUILD_EXAMPLE)
    add_executable(psi_analytics_eurocrypt19_example psi_analytics_example.cpp)

    target_link_libraries(psi_analytics_eurocrypt19_example PUBLIC
            psi_analytics_eurocrypt19
            )
    set_target_properties(psi_analytics_eurocrypt19_example
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif (PSI_ANALYTICS_BUILD_EXAMPLE)
