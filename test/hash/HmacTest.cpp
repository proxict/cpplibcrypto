#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/hash/Hmac.h"
#include "cpplibcrypto/hash/Sha1.h"
#include "cpplibcrypto/hash/Md5.h"

NAMESPACE_CRYPTO_BEGIN

static bool operator==(const StaticBufferBase<Byte>& lhs, const DynamicBuffer<Byte>& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (Size i = 0; i < lhs.size(); ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }
    return true;
}

static bool operator==(const DynamicBuffer<Byte>& lhs, const StaticBufferBase<Byte>& rhs) {
    return rhs == lhs;
}

TEST(HmacTest, sha1empty) {
    Hmac<Sha1> hmac(HmacKey{});
    hmac.update(String(""));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    hmac.finalize(digest);

    EXPECT_EQ(Hex::decode("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"), digest);
}

TEST(HmacTest, md5empty) {
    Hmac<Md5> hmac(HmacKey{});
    hmac.update(String(""));

    StaticBuffer<Byte, Md5::DIGEST_SIZE> digest(Md5::DIGEST_SIZE);
    hmac.finalize(digest);

    EXPECT_EQ(Hex::decode("74e6f7298a9c2d168935f58c001bad88"), digest);
}

TEST(HmacTest, md5case1) {
    Hmac<Md5> hmac(ByteBuffer{'k', 'e', 'y'});
    hmac.update(crypto::String("The quick brown fox jumps "));
    hmac.update(crypto::String("over the lazy dog"));

    StaticBuffer<Byte, Md5::DIGEST_SIZE> digest(Md5::DIGEST_SIZE);
    hmac.finalize(digest);

    EXPECT_EQ(Hex::decode("80070713463e7749b90c2dc24911e275"), digest);
}

TEST(HmacTest, sha1case1) {
    Hmac<Sha1> hmac(ByteBuffer{'k', 'e', 'y'});
    hmac.update(crypto::String("The quick brown fox jumps "));
    hmac.update(crypto::String("over the lazy dog"));

    StaticBuffer<Byte, Sha1::DIGEST_SIZE> digest(Sha1::DIGEST_SIZE);
    hmac.finalize(digest);

    EXPECT_EQ(Hex::decode("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"), digest);
}

TEST(HmacTest, reset) {
    Hmac<Md5> hmac(HmacKey{});
    hmac.update(String(""));

    StaticBuffer<Byte, Md5::DIGEST_SIZE> digest(Md5::DIGEST_SIZE);
    hmac.finalize(digest);
    EXPECT_EQ(Hex::decode("74e6f7298a9c2d168935f58c001bad88"), digest);

    hmac.reset();
    hmac.update(String(""));
    hmac.finalize(digest);
    EXPECT_EQ(Hex::decode("74e6f7298a9c2d168935f58c001bad88"), digest);
}

TEST(HmacTest, move) {
    Hmac<Md5> hmac(HmacKey{});
    hmac.update(String(""));

    StaticBuffer<Byte, Md5::DIGEST_SIZE> digest(Md5::DIGEST_SIZE);

    Hmac<Md5> hmacOther = std::move(hmac);
    hmacOther.finalize(digest);
    EXPECT_EQ(Hex::decode("74e6f7298a9c2d168935f58c001bad88"), digest);
}

NAMESPACE_CRYPTO_END
