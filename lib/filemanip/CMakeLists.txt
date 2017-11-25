add_library(filemanip STATIC
    src/FileManip.cpp
)

target_link_libraries(filemanip
    PRIVATE common
)

target_include_directories(filemanip PUBLIC include PRIVATE src)
