add_library(common STATIC
    src/Square.cpp
    src/Hex.cpp
)

target_include_directories(common PUBLIC include PRIVATE src)
