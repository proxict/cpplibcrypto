#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/hash/Sha2.h"

namespace crypto {

TEST(Sha224Test, empty) {
    Sha224 sha224;
    sha224.update(String(""));

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"), digest));
}

TEST(Sha224Test, case1) {
    Sha224 sha224;
    sha224.update(String("abc"));

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), digest));
}

TEST(Sha224Test, case2) {
    Sha224 sha224;
    sha224.update(String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"), digest));
}

TEST(Sha224Test, case3) {
    Sha224 sha224;
    sha224.update(String("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"));
    sha224.update(String("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"), digest));
}

TEST(Sha224Test, case4) {
    Sha224 sha224;
    DynamicBuffer<Byte> buffer;
    buffer.insert(buffer.end(), 0x61, 1000'000U);
    sha224.update(buffer);

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"), digest));
}

// This test takes ages to complete in debug configuration
TEST(Sha224Test, DISABLED_case5) {
    Sha224 sha224;
    String message("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    for (Size i = 0; i < 16'777'216; ++i) {
        sha224.update(message);
    }

    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);

    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"), digest));
}

TEST(Sha224Test, reset) {
    Sha224 sha224;
    sha224.update(String("abc"));
    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);
    sha224.finalize(digest);
    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), digest));

    sha224.reset();
    sha224.update(String("abc"));
    sha224.finalize(digest);
    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), digest));
}

TEST(Sha224Test, move) {
    Sha224 sha224;
    sha224.update(String("abc"));
    StaticBuffer<Byte, Sha224::DIGEST_SIZE> digest(Sha224::DIGEST_SIZE);

    Sha224 sha224other = std::move(sha224);
    sha224other.finalize(digest);
    EXPECT_TRUE(
        bufferUtils::equal(Hex::decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), digest));
}

} // namespace crypto
