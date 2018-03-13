add_library(cpplibcrypto STATIC
    src/common/Hex.cpp
)

target_include_directories(cpplibcrypto
    PUBLIC include
)
