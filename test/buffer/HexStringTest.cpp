#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/HexString.h"

NAMESPACE_CRYPTO_BEGIN

TEST(HexStringTest, basic) {
    EXPECT_EQ(HexString("ab"), HexString("AB"));
    EXPECT_EQ(HexString("aB"), HexString("Ab"));
}

TEST(HexStringTest, chaining) {
    HexString hs("ab");
    hs << HexString("cd");
    hs << HexString("ef") << HexString("00");

    EXPECT_EQ(HexString("abcdef00"), hs);
}

NAMESPACE_CRYPTO_END
