#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"
#include "cipher/CbcMode.h"
#include "padding/Pkcs7.h"
#include "common/ByteBuffer.h"
#include "common/Hex.h"
#include "common/HexString.h"

namespace crypto {

TEST(CbcAes128Test, cbcEncrypt1) {
    ByteBuffer IV;
    IV += HexString("000102030405060708090A0B0C0D0E0F");

    Aes aes;
    CbcEncrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("7649abac8119b246cee98e9b12e9197d"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcEncrypt2) {
    ByteBuffer IV;
    IV += HexString("7649ABAC8119B246CEE98E9B12E9197D");

    Aes aes;
    CbcEncrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("5086cb9b507219ee95db113a917678b2"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcEncrypt3) {
    ByteBuffer IV;
    IV += HexString("5086CB9B507219EE95DB113A917678B2");

    Aes aes;
    CbcEncrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("73bed6b8e3c1743b7116e69e22229516"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcEncrypt4) {
    ByteBuffer IV;
    IV += HexString("73BED6B8E3C1743B7116E69E22229516");

    Aes aes;
    CbcEncrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("3ff1caa1681fac09120eca307586e1a7"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcDecrypt1) {
    ByteBuffer IV;
    IV += HexString("000102030405060708090A0B0C0D0E0F");

    Aes aes;
    CbcDecrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("7649abac8119b246cee98e9b12e9197d");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcDecrypt2) {
    ByteBuffer IV;
    IV += HexString("7649ABAC8119B246CEE98E9B12E9197D");

    Aes aes;
    CbcDecrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("5086cb9b507219ee95db113a917678b2");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcDecrypt3) {
    ByteBuffer IV;
    IV += HexString("5086CB9B507219EE95DB113A917678B2");

    Aes aes;
    CbcDecrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("73bed6b8e3c1743b7116e69e22229516");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcDecrypt4) {
    ByteBuffer IV;
    IV += HexString("73BED6B8E3C1743B7116E69E22229516");

    Aes aes;
    CbcDecrypt cipher(aes, std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c"))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("3ff1caa1681fac09120eca307586e1a7");
    ByteBuffer out;
    out += cipher.update(buffer);
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcEncrypt5) {
    ByteBuffer IV;
    IV += HexString("73BED6B8E3C1743B7116E69E22229516");

    CbcMode<Aes>::Encryption encryptor(std::move(std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    ByteBuffer out;
    out += encryptor.update(buffer);
    EXPECT_EQ(HexString("3ff1caa1681fac09120eca307586e1a7"), HexString(Hex::encode(out)));
}

TEST(CbcAes128Test, cbcDecrypt5) {
    ByteBuffer IV;
    IV += HexString("73BED6B8E3C1743B7116E69E22229516");

    CbcMode<Aes>::Decryption encryptor(std::move(std::move(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")))), std::move(IV));

    ByteBuffer buffer;
    buffer += HexString("3ff1caa1681fac09120eca307586e1a7");
    ByteBuffer out;
    out += encryptor.update(buffer);
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));
}

} // namespace crypto
