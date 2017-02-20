add_library(common STATIC
    src/Square.cpp
)

target_include_directories(common PUBLIC include PRIVATE src)
