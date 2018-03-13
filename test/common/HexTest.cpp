#include <memory>

#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/common/Hex.h"

NAMESPACE_CRYPTO_BEGIN

TEST(HexTest, basic) {
    ByteBuffer s;
    s += Hex::decode("1234");

    ByteBuffer bb(std::move(s));
    bb += 0x56;
    bb += Hex::decode("789A");
    bb += Hex::decode("BCDE");
    bb += 0xF;

    EXPECT_EQ(8U, bb.size());
    EXPECT_EQ(0x9a, bb[4]);
}

TEST(HexTest, encodeZeros) {
    EXPECT_EQ("", Hex::encode(ByteBuffer{}));
    EXPECT_EQ("00", Hex::encode(ByteBuffer{ 0 }));
    EXPECT_EQ("0000", Hex::encode(ByteBuffer{ 0, 0 }));
    EXPECT_EQ("000000", Hex::encode(ByteBuffer{ 0, 0, 0 }));
    EXPECT_EQ("00000000", Hex::encode(ByteBuffer{ 0, 0, 0, 0 }));
    EXPECT_EQ("0000000000", Hex::encode(ByteBuffer{ 0, 0, 0, 0, 0 }));
    EXPECT_EQ("000000000000", Hex::encode(ByteBuffer{ 0, 0, 0, 0, 0, 0 }));
    EXPECT_EQ("00000000000000", Hex::encode(ByteBuffer{ 0, 0, 0, 0, 0, 0, 0 }));
    EXPECT_EQ("0000000000000000", Hex::encode(ByteBuffer{ 0, 0, 0, 0, 0, 0, 0, 0 }));
}

TEST(HexTest, decodeZeros) {
    EXPECT_EQ(ByteBuffer({}), Hex::decode(""));
    EXPECT_EQ(ByteBuffer({ 0 }), Hex::decode("00"));
    EXPECT_EQ(ByteBuffer({ 0, 0 }), Hex::decode("0000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0 }), Hex::decode("000000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0, 0 }), Hex::decode("00000000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0, 0, 0 }), Hex::decode("0000000000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0, 0, 0, 0 }), Hex::decode("000000000000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0, 0, 0, 0, 0 }), Hex::decode("00000000000000"));
    EXPECT_EQ(ByteBuffer({ 0, 0, 0, 0, 0, 0, 0, 0 }), Hex::decode("0000000000000000"));
}

TEST(HexTest, encodeData) {
    EXPECT_EQ("ff", Hex::encode(ByteBuffer{ 255 }));
    EXPECT_EQ("00ff", Hex::encode(ByteBuffer{ 0, 255 }));
    EXPECT_EQ("ff00", Hex::encode(ByteBuffer{ 255, 0 }));
}

TEST(HexTest, decodeData) {
    EXPECT_EQ(ByteBuffer({ 255 }), Hex::decode("ff"));
    EXPECT_EQ(ByteBuffer({ 0, 255 }), Hex::decode("00ff"));
    EXPECT_EQ(ByteBuffer({ 255, 0 }), Hex::decode("ff00"));
}

TEST(HexTest, exception) {
    EXPECT_THROW(Hex::decode("1"), Exception);
    EXPECT_THROW(Hex::decode("123"), Exception);
    EXPECT_THROW(Hex::decode("pp"), Exception);
    EXPECT_THROW(Hex::decode("0q"), Exception);
}

NAMESPACE_CRYPTO_END
