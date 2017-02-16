find_path(GTEST_INCLUDE_DIR gtest/gtest.h HINTS $ENV{GTEST_ROOT}/include ${GTEST_ROOT}/include)
find_library(GTEST_LIBRARY NAMES gtest HINTS ENV GTEST_ROOT ${GTEST_ROOT} PATH_SUFFIXES lib)
find_library(GMOCK_LIBRARY NAMES gmock HINTS ENV GTEST_ROOT ${GTEST_ROOT} PATH_SUFFIXES lib)

if(NOT GTEST_INCLUDE_DIR OR NOT GTEST_LIBRARY OR NOT GMOCK_LIBRARY)
    message("googletest not found, unittests disabled")
else()
    add_executable(unittests
        main.cpp
        common/SquareTest.cpp
    )

    target_include_directories(unittests PRIVATE ${GTEST_INCLUDE_DIR})

    target_link_libraries(unittests
        PRIVATE common
        PRIVATE ${GTEST_LIBRARY}
        PRIVATE ${GMOCK_LIBRARY}
        PRIVATE pthread
    )
endif()
