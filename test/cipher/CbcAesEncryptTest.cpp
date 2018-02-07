#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"
#include "cipher/AesIv.h"
#include "cipher/CbcMode.h"
#include "common/DynamicBuffer.h"
#include "common/Hex.h"
#include "common/HexString.h"
#include "padding/Pkcs7.h"

namespace crypto {

TEST(CbcAes128EncryptTest, cbcEncryptBlock1) {
    AesIv iv(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), iv);

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("7649abac8119b246cee98e9b12e9197d"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes128EncryptTest, cbcEncryptBlock2) {
    AesIv iv(HexString("7649ABAC8119B246CEE98E9B12E9197D"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), iv);

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("5086cb9b507219ee95db113a917678b2"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes128EncryptTest, cbcEncryptBlock3) {
    AesIv iv(HexString("5086CB9B507219EE95DB113A917678B2"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), iv);

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("73bed6b8e3c1743b7116e69e22229516"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes128EncryptTest, cbcEncryptBlock4) {
    AesIv iv(HexString("73BED6B8E3C1743B7116E69E22229516"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), iv);

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("3ff1caa1681fac09120eca307586e1a7"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes192EncryptTest, cbcEncryptBlock1) {
    AesIv iv(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), iv);

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("4f021db243bc633d7178183a9fa071e8"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes192EncryptTest, cbcEncryptBlock2) {
    AesIv iv(HexString("4F021DB243BC633D7178183A9FA071E8"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), iv);

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("b4d9ada9ad7dedf4e5e738763f69145a"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes192EncryptTest, cbcEncryptBlock3) {
    AesIv iv(HexString("B4D9ADA9AD7DEDF4E5E738763F69145A"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), iv);

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("571b242012fb7ae07fa9baac3df102e0"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes192EncryptTest, cbcEncryptBlock4) {
    AesIv iv(HexString("571B242012FB7AE07FA9BAAC3DF102E0"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), iv);

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("08b0e27988598881d920a9e64f5615cd"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes256EncryptTest, cbcEncryptBlock1) {
    AesIv iv(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("f58c4c04d6e5f1ba779eabfb5f7bfbd6"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes256EncryptTest, cbcEncryptBlock2) {
    AesIv iv(HexString("F58C4C04D6E5F1BA779EABFB5F7BFBD6"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("9cfc4e967edb808d679f777bc6702c7d"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes256EncryptTest, cbcEncryptBlock3) {
    AesIv iv(HexString("9CFC4E967EDB808D679F777BC6702C7D"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("39f23369a9d9bacfa530e26304231461"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes256EncryptTest, cbcEncryptBlock4) {
    AesIv iv(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("b2eb05e2c39be9fcda6c19078c6a9d1b"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
}

TEST(CbcAes128EncryptTest, cbcEncryptMultipleBlocks) {
    AesIv iv(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("000102030405060708090a0b0c0d0e0f");
    buffer += HexString("101112131415161718191a1b1c1d1e1f");
    buffer += HexString("00102030405060708090a0b0c0d0e0f0");

    StaticBuffer<Byte, 48> out;
    const Size processed = cipher.update(buffer, out);
    buffer.erase(0, processed);
    cipher.doFinal(buffer, out, PaddingNone());

    ByteBuffer expected;
    expected += HexString("3f81c441d47f750c13ce8438cf7bcb12");
    expected += HexString("1f48175c755f420ef85d6af6b21507a9");
    expected += HexString("70a9724f666aaf0c4879b23b87460a0f");
    EXPECT_EQ(expected, HexString(Hex::encode(out)));
    EXPECT_EQ(48U, processed);
}

TEST(CbcAes128EncryptTest, cbcEncryptMultipleBlocksPadding) {
    AesIv iv(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("000102030405060708090a0b0c0d0e0f");
    buffer += HexString("101112131415161718191a1b1c1d1e1f");
    buffer += HexString("00102030405060708090a0b0c0d0e0f0");

    StaticBuffer<Byte, 64> out;
    const Size processed = cipher.update(buffer, out);
    buffer.erase(0, processed);
    cipher.doFinal(buffer, out, Pkcs7());

    ByteBuffer expected;
    expected += HexString("3f81c441d47f750c13ce8438cf7bcb12");
    expected += HexString("1f48175c755f420ef85d6af6b21507a9");
    expected += HexString("70a9724f666aaf0c4879b23b87460a0f");
    expected += HexString("f3382bb0dbc13fd8d9064a4261b62f35");
    EXPECT_EQ(expected, HexString(Hex::encode(out)));
    EXPECT_EQ(48U, processed);
}

TEST(CbcAes256EncryptTest, cbcEncryptResetChain) {
    AesIv iv(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcEncrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), iv);

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");
    StaticBuffer<Byte, 16> out;
    const Size processed = cipher.update(buffer, out);
    EXPECT_EQ(HexString("b2eb05e2c39be9fcda6c19078c6a9d1b"), HexString(Hex::encode(out)));
    EXPECT_EQ(16U, processed);
    cipher.resetChain();
    StaticBuffer<Byte, 16> out2;
    const Size processed2 = cipher.update(buffer, out2);
    EXPECT_EQ(HexString("b2eb05e2c39be9fcda6c19078c6a9d1b"), HexString(Hex::encode(out2)));
    EXPECT_EQ(16U, processed2);
}

} // namespace crypto
