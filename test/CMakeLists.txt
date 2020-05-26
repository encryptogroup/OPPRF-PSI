add_executable(psi_analytics_eurocrypt19_test
        psi_analytics_eurocrypt19_test.cpp
        )

target_link_libraries(psi_analytics_eurocrypt19_test PUBLIC
        psi_analytics_eurocrypt19
        gtest
        )

#target_include_directories(psi_analytics_eurocrypt19_test PRIVATE
#        ${CMAKE_PROJECT_DIR}
#        ${CMAKE_PROJECT_DIR}/extern/ABY/extern/ENCRYPTO_utils/extern/googletest/googletext/include
#        )
