#include <memory>

#include "gtest/gtest.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/cipher/Aes.h"
#include "cpplibcrypto/common/Hex.h"

namespace crypto {

using ByteBufferSlice = BufferSlice<Byte>;

TEST(Aes128EncryptTest, encrypt1) {
    Aes aes(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("3ad77bb40d7a3660a89ecaf32466ef97"), HexString(Hex::encode(buffer)));
}

TEST(Aes128EncryptTest, encrypt2) {
    Aes aes(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("f5d3d58503b9699de785895a96fdbaaf"), HexString(Hex::encode(buffer)));
}

TEST(Aes128EncryptTest, encrypt3) {
    Aes aes(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("43b1cd7f598ece23881b00e3ed030688"), HexString(Hex::encode(buffer)));
}

TEST(Aes128EncryptTest, encrypt4) {
    Aes aes(AesKey(HexString("2b7e151628aed2a6abf7158809cf4f3c")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("7b0c785e27e8ad3f8223207104725dd4"), HexString(Hex::encode(buffer)));
}

TEST(Aes192EncryptTest, encrypt1) {
    Aes aes(AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("bd334f1d6e45f25ff712a214571fa5cc"), HexString(Hex::encode(buffer)));
}

TEST(Aes192EncryptTest, encrypt2) {
    Aes aes(AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("974104846d0ad3ad7734ecb3ecee4eef"), HexString(Hex::encode(buffer)));
}

TEST(Aes192EncryptTest, encrypt3) {
    Aes aes(AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("ef7afd2270e2e60adce0ba2face6444e"), HexString(Hex::encode(buffer)));
}

TEST(Aes192EncryptTest, encrypt4) {
    Aes aes(AesKey(HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("9a4b41ba738d6c72fb16691603c18e0e"), HexString(Hex::encode(buffer)));
}

TEST(Aes256EncryptTest, encrypt1) {
    Aes aes(AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("f3eed1bdb5d2a03c064b5a7e3db181f8"), HexString(Hex::encode(buffer)));
}

TEST(Aes256EncryptTest, encrypt2) {
    Aes aes(AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("591ccb10d410ed26dc5ba74a31362870"), HexString(Hex::encode(buffer)));
}

TEST(Aes256EncryptTest, encrypt3) {
    Aes aes(AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("b6ed21b99ca6f4f9f153e7b1beafed1d"), HexString(Hex::encode(buffer)));
}

TEST(Aes256EncryptTest, encrypt4) {
    Aes aes(AesKey(HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")));

    StaticBuffer<Byte, 16> buffer;
    buffer << HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("23304b7a39f9f3ff067d8d8f9e24ecc7"), HexString(Hex::encode(buffer)));
}

} // namespace crypto
