add_library(filemanip_objects OBJECT
    src/FileManip.cpp
)

target_include_directories(filemanip_objects
    PUBLIC include
    PRIVATE ${common_includes}
)

get_property(filemanip_includes_local TARGET filemanip_objects PROPERTY INCLUDE_DIRECTORIES)
set(filemanip_includes ${filemanip_includes_local} CACHE STRING "Include directories for filemanip module")

