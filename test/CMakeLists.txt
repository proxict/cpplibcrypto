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

target_include_directories(unittests
    PRIVATE ${common_includes}
    PRIVATE ${cipher_includes}
    PRIVATE ${padding_includes}
    PRIVATE ${filemanip_includes}
)

target_link_libraries(unittests
    PRIVATE cpplibcrypto
    PRIVATE gmock
    PRIVATE gtest
)

