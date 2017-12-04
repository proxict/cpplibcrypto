cmake_minimum_required(VERSION 3.0)
project(cpplibcrypto VERSION 1.0.0 LANGUAGES C CXX)

include(cmake/compiler-config.txt)
include(cmake/doxygen.txt)
include(cmake/coverage.txt)

add_subdirectory(lib)
add_subdirectory(tools/sandbox)
if (NOT TARGET gmock AND NOT TARGET gtest)
    add_subdirectory(external/googletest)
endif()
add_subdirectory(test)
