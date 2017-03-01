add_library(cipher STATIC
    src/AES.cpp
)

target_link_libraries(cipher
    PRIVATE common
)

target_include_directories(cipher PUBLIC include PRIVATE src)
