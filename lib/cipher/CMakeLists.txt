add_library(cipher STATIC
    src/Aes.cpp
)

target_link_libraries(cipher
    PRIVATE common
    PRIVATE padding
)

target_include_directories(cipher
    PUBLIC ../padding/include
    PUBLIC include
    PRIVATE src
)
