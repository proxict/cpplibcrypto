#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"
#include "cipher/AesIV.h"
#include "cipher/CbcMode.h"
#include "padding/Pkcs7.h"
#include "common/DynamicBuffer.h"
#include "common/Hex.h"
#include "common/HexString.h"

namespace crypto {

TEST(CbcAes128DecryptTest, cbcDecrypt1) {
    AesIV IV(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), IV);

    ByteBuffer buffer;
    buffer += HexString("7649abac8119b246cee98e9b12e9197d");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(out)));
}

TEST(CbcAes128DecryptTest, cbcDecrypt2) {
    AesIV IV(HexString("7649ABAC8119B246CEE98E9B12E9197D"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), IV);

    ByteBuffer buffer;
    buffer += HexString("5086cb9b507219ee95db113a917678b2");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(out)));
}

TEST(CbcAes128DecryptTest, cbcDecrypt3) {
    AesIV IV(HexString("5086CB9B507219EE95DB113A917678B2"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), IV);

    ByteBuffer buffer;
    buffer += HexString("73bed6b8e3c1743b7116e69e22229516");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(out)));
}

TEST(CbcAes128DecryptTest, cbcDecrypt4) {
    AesIV IV(HexString("73BED6B8E3C1743B7116E69E22229516"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")), IV);

    ByteBuffer buffer;
    buffer += HexString("3ff1caa1681fac09120eca307586e1a7");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));
}

TEST(CbcAes192DecryptTest, cbcDecrypt1) {
    AesIV IV(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), IV);

    ByteBuffer buffer;
    buffer += HexString("4f021db243bc633d7178183a9fa071e8");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(out)));
}

TEST(CbcAes192DecryptTest, cbcDecrypt2) {
    AesIV IV(HexString("4F021DB243BC633D7178183A9FA071E8"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), IV);

    ByteBuffer buffer;
    buffer += HexString("b4d9ada9ad7dedf4e5e738763f69145a");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(out)));
}

TEST(CbcAes192DecryptTest, cbcDecrypt3) {
    AesIV IV(HexString("B4D9ADA9AD7DEDF4E5E738763F69145A"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), IV);

    ByteBuffer buffer;
    buffer += HexString("571b242012fb7ae07fa9baac3df102e0");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(out)));
}

TEST(CbcAes192DecryptTest, cbcDecrypt4) {
    AesIV IV(HexString("571B242012FB7AE07FA9BAAC3DF102E0"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")), IV);

    ByteBuffer buffer;
    buffer += HexString("08b0e27988598881d920a9e64f5615cd");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));
}

TEST(CbcAes256DecryptTest, cbcDecrypt1) {
    AesIV IV(HexString("000102030405060708090A0B0C0D0E0F"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), IV);

    ByteBuffer buffer;
    buffer += HexString("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(out)));
}

TEST(CbcAes256DecryptTest, cbcDecrypt2) {
    AesIV IV(HexString("F58C4C04D6E5F1BA779EABFB5F7BFBD6"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), IV);

    ByteBuffer buffer;
    buffer += HexString("9cfc4e967edb808d679f777bc6702c7d");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(out)));
}

TEST(CbcAes256DecryptTest, cbcDecrypt3) {
    AesIV IV(HexString("9CFC4E967EDB808D679F777BC6702C7D"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), IV);

    ByteBuffer buffer;
    buffer += HexString("39f23369a9d9bacfa530e26304231461");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(out)));
}

TEST(CbcAes256DecryptTest, cbcDecrypt4) {
    AesIV IV(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), IV);

    ByteBuffer buffer;
    buffer += HexString("b2eb05e2c39be9fcda6c19078c6a9d1b");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));
}

TEST(CbcAes256DecryptResetChainTest, cbcDecryptResetChain1) {
    AesIV IV(HexString("39F23369A9D9BACFA530E26304231461"));

    Aes aes;
    CbcDecrypt cipher(aes, AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")), IV);

    ByteBuffer buffer;
    buffer += HexString("b2eb05e2c39be9fcda6c19078c6a9d1b");
    StaticBuffer<Byte, 16> out;
    Size processed = cipher.update(buffer, out);
    EXPECT_EQ(0U, processed);
    cipher.doFinal(buffer, out, PaddingNone());
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out)));

    cipher.resetChain();
    StaticBuffer<Byte, 16> out2;
    Size processed2 = cipher.update(buffer, out2);
    EXPECT_EQ(0U, processed2);
    cipher.doFinal(buffer, out2, PaddingNone());
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(out2)));
}

} // namespace crypto
