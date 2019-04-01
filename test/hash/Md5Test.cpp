#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/hash/Md5.h"

NAMESPACE_CRYPTO_BEGIN

TEST(Md5Test, empty) {
    Md5 md5;
    md5.update(String(""));

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("d41d8cd98f00b204e9800998ecf8427e"), digest));
}

TEST(Md5Test, case1) {
    Md5 md5;
    md5.update(String("a"));

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("0cc175b9c0f1b6a831c399e269772661"), digest));
}

TEST(Md5Test, case2) {
    Md5 md5;
    md5.update(String("abc"));

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("900150983cd24fb0d6963f7d28e17f72"), digest));
}

TEST(Md5Test, case3) {
    Md5 md5;
    md5.update(String("abcdefghijklmnopqrstuvwxyz"));

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("c3fcd3d76192e4007dfb496cca67e13b"), digest));
}

TEST(Md5Test, case4) {
    Md5 md5;
    md5.update(String("message digest"));

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("f96b697d7cb7938d525a2f31aaf161d0"), digest));
}

TEST(Md5Test, case5) {
    Md5 md5;
    DynamicBuffer<Byte> buffer;
    buffer.insert(buffer.end(), 0x61, 1000'000U);
    md5.update(buffer);

    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("7707d6ae4e027c70eea2a935c2296f21"), digest));
}

TEST(Md5Test, reset) {
    Md5 md5;
    md5.update(String("abc"));
    StaticBuffer<Byte, 16> digest(16);
    md5.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("900150983cd24fb0d6963f7d28e17f72"), digest));

    md5.reset();
    md5.update(String("abc"));
    md5.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("900150983cd24fb0d6963f7d28e17f72"), digest));
}

TEST(Md5Test, move) {
    Md5 md5;
    md5.update(String("abc"));
    StaticBuffer<Byte, 16> digest(16);

    Md5 md5other = std::move(md5);
    md5other.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("900150983cd24fb0d6963f7d28e17f72"), digest));
}

NAMESPACE_CRYPTO_END
