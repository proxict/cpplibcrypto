add_library(padding STATIC
    src/Pkcs7.cpp
)

target_link_libraries(padding
    PRIVATE common
)

target_include_directories(padding PUBLIC include PRIVATE src)
