cmake_minimum_required(VERSION 3.0)
project(cpplibcrypto VERSION 1.0.0 LANGUAGES C CXX)

include(cmake/compiler-config.txt)
include(cmake/doxygen.txt)
include(cmake/coverage.txt)

add_subdirectory(external/googletest)

add_subdirectory(lib/common)
add_subdirectory(lib/cipher)
add_subdirectory(lib/padding)
add_subdirectory(lib/filemanip)
add_subdirectory(tools/sandbox)
add_subdirectory(test)
