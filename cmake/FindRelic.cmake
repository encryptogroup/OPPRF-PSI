find_package(PkgConfig)

set(RLC_LIBRARY "${PSI_ANALYTICS_BINARY_ROOT}/extern/ABY/lib/librelic_s.a")
set(Relic_INCLUDE_DIR "${PSI_ANALYTICS_BINARY_ROOT}/include")
set(RLC_INCLUDE_DIR ${Relic_INCLUDE_DIR})

find_package_handle_standard_args(Relic "Found relic" Relic_INCLUDE_DIR)
