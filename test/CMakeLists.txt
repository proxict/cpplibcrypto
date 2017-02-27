add_executable(unittests
    main.cpp
    common/SquareTest.cpp
    common/ByteBufferTest.cpp
    common/HexTest.cpp
    common/HexStringTest.cpp
)

target_link_libraries(unittests
    PRIVATE common
    PRIVATE gtest
    PRIVATE gmock
)
