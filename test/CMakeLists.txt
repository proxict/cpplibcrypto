if (NOT TARGET gmock AND NOT TARGET gtest)
    add_subdirectory(external/googletest)
endif()

add_executable(unittests
    main.cpp
    buffer/DynamicBufferTest.cpp
    buffer/StaticBufferTest.cpp
    buffer/HexStringTest.cpp
    common/HexTest.cpp
    hash/Sha1Test.cpp
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

