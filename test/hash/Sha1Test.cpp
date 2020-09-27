#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/hash/Sha1.h"

namespace crypto {

TEST(Sha1Test, empty) {
    Sha1 sha1;
    sha1.update(String(""));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709"), digest));
}

TEST(Sha1Test, case1) {
    Sha1 sha1;
    sha1.update(String("abc"));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d"), digest));
}

TEST(Sha1Test, case2) {
    Sha1 sha1;
    sha1.update(String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("84983e441c3bd26ebaae4aa1f95129e5e54670f1"), digest));
}

TEST(Sha1Test, case3) {
    Sha1 sha1;
    sha1.update(String("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"));
    sha1.update(String("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("a49b2446a02c645bf419f995b67091253a04a259"), digest));
}

TEST(Sha1Test, case4) {
    Sha1 sha1;
    DynamicBuffer<Byte> buffer;
    buffer.insert(buffer.end(), 0x61, 1000'000U);
    sha1.update(buffer);

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f"), digest));
}

// This test takes ages to complete in debug configuration
TEST(Sha1Test, DISABLED_case5) {
    Sha1 sha1;
    String message("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    for (Size i = 0; i < 16'777'216; ++i) {
        sha1.update(message);
    }

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(Hex::decode("7789f0c9ef7bfc40d93311143dfbe69e2017f592"), digest));
}

TEST(Sha1Test, reset) {
    Sha1 sha1;
    sha1.update(String("abc"));
    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    sha1.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d"), digest));

    sha1.reset();
    sha1.update(String("abc"));
    sha1.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d"), digest));
}

TEST(Sha1Test, move) {
    Sha1 sha1;
    sha1.update(String("abc"));
    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);

    Sha1 sha1other = std::move(sha1);
    sha1other.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d"), digest));
}

} // namespace crypto
