if (NOT TARGET gmock AND NOT TARGET gtest)
    add_subdirectory(external/googletest)
endif()

add_executable(unittests
    main.cpp
    buffer/DynamicBufferTest.cpp
    buffer/BackInserterTest.cpp
    buffer/StaticBufferTest.cpp
    buffer/HexStringTest.cpp
    common/HexTest.cpp
    hash/Sha1Test.cpp
    hash/Sha224Test.cpp
    hash/Sha256Test.cpp
    hash/Md5Test.cpp
    hash/HmacTest.cpp
    kdf/PbkdfTest.cpp
    cipher/AesCoreTest.cpp
    cipher/AesKeyScheduleTest.cpp
    cipher/AesDecryptTest.cpp
    cipher/AesEncryptTest.cpp
    cipher/CbcAesDecryptTest.cpp
    cipher/CbcAesEncryptTest.cpp
)

target_link_libraries(unittests
    PRIVATE cpplibcrypto
    PRIVATE gmock
    PRIVATE gtest
)

