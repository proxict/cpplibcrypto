cmake_minimum_required(VERSION 3.0)
project(cpplibcrypto VERSION 1.0.0 LANGUAGES C CXX)

include(cmake/compiler-config.txt)
include(cmake/doxygen.txt)

add_subdirectory(lib/common)
add_subdirectory(tools/sandbox)
add_subdirectory(test)
