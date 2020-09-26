#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/hash/Sha2.h"

NAMESPACE_CRYPTO_BEGIN

TEST(Sha256Test, empty) {
    Sha256 sha256;
    sha256.update(String(""));

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), digest));
}

TEST(Sha256Test, case1) {
    Sha256 sha256;
    sha256.update(String("abc"));

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), digest));
}

TEST(Sha256Test, case2) {
    Sha256 sha256;
    sha256.update(String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), digest));
}

TEST(Sha256Test, case3) {
    Sha256 sha256;
    sha256.update(String("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"));
    sha256.update(String("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"), digest));
}

TEST(Sha256Test, case4) {
    Sha256 sha256;
    DynamicBuffer<Byte> buffer;
    buffer.insert(buffer.end(), 0x61, 1000'000U);
    sha256.update(buffer);

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), digest));
}

// This test takes ages to complete in debug configuration
TEST(Sha256Test, DISABLED_case5) {
    Sha256 sha256;
    String message("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    for (Size i = 0; i < 16'777'216; ++i) {
        sha256.update(message);
    }

    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);

    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"), digest));
}

TEST(Sha256Test, reset) {
    Sha256 sha256;
    sha256.update(String("abc"));
    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);
    sha256.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), digest));

    sha256.reset();
    sha256.update(String("abc"));
    sha256.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), digest));
}

TEST(Sha256Test, move) {
    Sha256 sha256;
    sha256.update(String("abc"));
    StaticBuffer<Byte, Sha256::DIGEST_SIZE> digest(Sha256::DIGEST_SIZE);

    Sha256 sha256other = std::move(sha256);
    sha256other.finalize(digest);
    EXPECT_TRUE(bufferUtils::equal(
        Hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), digest));
}

NAMESPACE_CRYPTO_END
