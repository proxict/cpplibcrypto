add_executable(unittests
    main.cpp
    common/ByteBufferTest.cpp
    common/StaticByteBufferTest.cpp
    common/HexTest.cpp
    common/HexStringTest.cpp
    cipher/AesCoreTest.cpp
    cipher/AesKeyScheduleTest.cpp
    cipher/AesDecryptTest.cpp
    cipher/AesEncryptTest.cpp
    cipher/CbcAesDecryptTest.cpp
    cipher/CbcAesEncryptTest.cpp
)

target_link_libraries(unittests
    PRIVATE cipher
    PRIVATE padding
    PRIVATE common
    PRIVATE gtest
    PRIVATE gmock
)
