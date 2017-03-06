add_library(cipher STATIC
    src/Aes.cpp
)

target_link_libraries(cipher
    PRIVATE common
)

target_include_directories(cipher PUBLIC include PRIVATE src)
