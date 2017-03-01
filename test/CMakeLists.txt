add_executable(unittests
    main.cpp
    common/SquareTest.cpp
    common/ByteBufferTest.cpp
    common/HexTest.cpp
    common/HexStringTest.cpp
    cipher/AesTest.cpp
)

target_link_libraries(unittests
    PRIVATE cipher
    PRIVATE common
    PRIVATE gtest
    PRIVATE gmock
)
