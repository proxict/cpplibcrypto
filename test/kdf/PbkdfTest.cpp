#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/kdf/Pbkdf.h"

namespace crypto {

TEST(Pbkdf2Test, case1) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);
    kdf.derive(dk.size(), dk, 1);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6"), dk));
}

TEST(Pbkdf2Test, case2) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);
    kdf.derive(dk.size(), dk, 2);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), dk));
}

TEST(Pbkdf2Test, case3) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);
    kdf.derive(dk.size(), dk, 4096);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("4b007901b765489abead49d926f721d065a429c1"), dk));
}

// This test takes ages to complete in debug configuration
TEST(Pbkdf2Test, DISABLED_case4) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);
    kdf.derive(dk.size(), dk, 16777216);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"), dk));
}

TEST(Pbkdf2Test, case5) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("passwordPASSWORDpassword")),
                       crypto::Salt(crypto::String("saltSALTsaltSALTsaltSALTsaltSALTsalt")));
    crypto::StaticBuffer<crypto::Byte, 25> dk(25);
    kdf.derive(dk.size(), dk, 4096);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"), dk));
}

TEST(Pbkdf2Test, case6) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("pass\0word", 9)),
                       crypto::Salt(crypto::String("sa\0lt", 5)));
    crypto::StaticBuffer<crypto::Byte, 16> dk(16);
    kdf.derive(dk.size(), dk, 4096);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("56fa6aa75548099dcc37d7f03425e0c3"), dk));
}

TEST(Pbkdf2Test, move) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);

    crypto::Pbkdf2 moved(std::move(kdf));
    moved.derive(dk.size(), dk, 1);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6"), dk));
}

TEST(Pbkdf2Test, setPasswordAndSalt) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("")), crypto::Salt(crypto::String("")));
    kdf.setPassword(crypto::Password(crypto::String("password")));
    kdf.setSalt(crypto::Salt(crypto::String("salt")));

    crypto::StaticBuffer<crypto::Byte, 20> dk(20);
    kdf.derive(dk.size(), dk, 1);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6"), dk));
}

TEST(Pbkdf2Test, deriveMultipleKeys) {
    crypto::Pbkdf2 kdf(crypto::Password(crypto::String("password")), crypto::Salt(crypto::String("salt")));
    crypto::StaticBuffer<crypto::Byte, 20> dk(20);

    kdf.derive(dk.size(), dk, 1);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6"), dk));

    kdf.derive(dk.size(), dk, 2);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), dk));

    dk.resize(16);
    kdf.setPassword(crypto::Password(crypto::String("pass\0word", 9)));
    kdf.setSalt(crypto::Password(crypto::String("sa\0lt", 5)));
    kdf.derive(dk.size(), dk, 4096);
    EXPECT_TRUE(bufferUtils::equal(Hex::decode("56fa6aa75548099dcc37d7f03425e0c3"), dk));
}

} // namespace crypto
