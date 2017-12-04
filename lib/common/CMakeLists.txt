add_library(common_objects OBJECT
    src/Hex.cpp
)

target_include_directories(common_objects
    PUBLIC include
)

get_property(common_includes_local TARGET common_objects PROPERTY INCLUDE_DIRECTORIES)
set(common_includes ${common_includes_local} CACHE STRING "Include directories for common module")

