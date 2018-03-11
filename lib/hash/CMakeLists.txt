add_library(hash_objects OBJECT
    src/Hash.cpp
)

target_include_directories(hash_objects
    PUBLIC include
)

get_property(hash_includes_local TARGET hash_objects PROPERTY INCLUDE_DIRECTORIES)
set(hash_includes ${hash_includes_local} CACHE STRING "Include directories for hash module")

