#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"
#include "common/ByteBuffer.h"
#include "common/Hex.h"
#include "common/HexString.h"

namespace crypto {

struct AesTestSubroutines : public testing::Test, Aes {
    AesTestSubroutines() : Aes(Aes::Aes256) {}
    virtual ~AesTestSubroutines() = default;
};

TEST_F(AesTestSubroutines, subBytes) {
    ByteBuffer buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    subBytes(buffer);
    subBytesInv(buffer);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

TEST_F(AesTestSubroutines, shiftRows) {
    /*
      original state:
      00 04 08 0C
      01 05 09 0D
      02 06 0A 0E
      03 07 0B 0F

      expected state after shiftRows:
      00 04 08 0C
      05 09 0D 01
      0A 0E 02 06
      0F 03 07 0B
    */

    ByteBuffer buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    shiftRows(buffer);
    EXPECT_EQ(HexString("00050A0F04090E03080D02070C01060B"), buffer);
    shiftRowsInv(buffer);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

TEST_F(AesTestSubroutines, mixColumns) {
    ByteBuffer buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    mixColumns(buffer);
    EXPECT_EQ(HexString("02070005060304010a0f080d0e0b0c09"), buffer);
    mixColumnsInv(buffer);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

TEST(Aes128Test, keySchedule1) {
    ByteBuffer key;
    key += HexString("00000000000000000000000000000000");
    Aes aes(Aes::Aes128, std::move(key));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("90973450696ccffaf2f457330b0fac99"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("ee06da7b876a1581759e42b27e91ee2b"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("7f2e2b88f8443e098dda7cbbf34b9290"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("ec614b851425758c99ff09376ab49ba7"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("217517873550620bacaf6b3cc61bf09b"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("0ef903333ba9613897060a04511dfa9f"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("b1d4d8e28a7db9da1d7bb3de4c664941"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("b4ef5bcb3e92e21123e951cf6f8f188e"), aes.getNthRoundKey(10));
}

TEST(Aes128Test, keySchedule2) {
    ByteBuffer key;
    key += HexString("ffffffffffffffffffffffffffffffff");
    Aes aes(Aes::Aes128, std::move(key));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("adaeae19bab8b80f525151e6454747f0"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("090e2277b3b69a78e1e7cb9ea4a08c6e"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("e16abd3e52dc2746b33becd8179b60b6"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("e5baf3ceb766d488045d385013c658e6"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("71d07db3c6b6a93bc2eb916bd12dc98d"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("e90d208d2fbb89b6ed5018dd3c7dd150"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("96337366b988fad054d8e20d68a5335d"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("8bf03f233278c5f366a027fe0e0514a3"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("d60a3588e472f07b82d2d7858cd7c326"), aes.getNthRoundKey(10));
}

TEST(Aes128Test, keySchedule3) {
    ByteBuffer key;
    key += HexString("000102030405060708090a0b0c0d0e0f");
    Aes aes(Aes::Aes128, std::move(key));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("d6aa74fdd2af72fadaa678f1d6ab76fe"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("b692cf0b643dbdf1be9bc5006830b3fe"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("b6ff744ed2c2c9bf6c590cbf0469bf41"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("47f7f7bc95353e03f96c32bcfd058dfd"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("3caaa3e8a99f9deb50f3af57adf622aa"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("5e390f7df7a69296a7553dc10aa31f6b"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("14f9701ae35fe28c440adf4d4ea9c026"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("47438735a41c65b9e016baf4aebf7ad2"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("549932d1f08557681093ed9cbe2c974e"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("13111d7fe3944a17f307a78b4d2b30c5"), aes.getNthRoundKey(10));
}

TEST(Aes192Test, keySchedule1) {
    ByteBuffer key;
    key += HexString("000000000000000000000000000000000000000000000000");
    Aes aes(Aes::Aes192, std::move(key));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("00000000000000006263636362636363"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa90973450696ccffa"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("f2f457330b0fac9990973450696ccffa"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("c81d19a9a171d65353858160588a2df9"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("c81d19a9a171d6537bebf49bda9a22c8"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("891fa3a8d1958e51198897f8b8f941ab"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("c26896f718f2b43f91ed1797407899c6"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("59f00e3ee1094f9583ecbc0f9b1e0830"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("0af31fa74a8b8661137b885ff272c7ca"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("432ac886d834c0b6d2c7df11984c5970"), aes.getNthRoundKey(12));
}

TEST(Aes192Test, keySchedule2) {
    ByteBuffer key;
    key += HexString("ffffffffffffffffffffffffffffffffffffffffffffffff");
    Aes aes(Aes::Aes192, std::move(key));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("ffffffffffffffffe8e9e9e917161616"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("adaeae19bab8b80f525151e6454747f0"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("adaeae19bab8b80fc5c2d8ed7f7a60e2"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("2d2b3104686c76f4c5c2d8ed7f7a60e2"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("1712403f686820dd454311d92d2f672d"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("e8edbfc09797df228f8cd3b7e7e4f36a"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("a2a7e2b38f88859e67653a5ef0f2e57c"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("2655c33bc1b130516316d2e2ec9e577c"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("8bfb6d227b09885e67919b1aa620ab4b"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("c53679a929a82ed5a25343f7d95acba9"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("598e482fffaee3643a989acd1330b418"), aes.getNthRoundKey(12));
}

TEST(Aes192Test, keySchedule3) {
    ByteBuffer key;
    key += HexString("000102030405060708090a0b0c0d0e0f1011121314151617");
    Aes aes(Aes::Aes192, std::move(key));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("10111213141516175846f2f95c43f4fe"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("544afef55847f0fa4856e2e95c43f4fe"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("40f949b31cbabd4d48f043b810b7b342"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("58e151ab04a2a5557effb5416245080c"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("2ab54bb43a02f8f662e3a95d66410c08"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("f501857297448d7ebdf1c6ca87f33e3c"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("e510976183519b6934157c9ea351f1e0"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("1ea0372a995309167c439e77ff12051e"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("dd7e0e887e2fff68608fc842f9dcc154"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("859f5f237a8d5a3dc0c02952beefd63a"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("de601e7827bcdf2ca223800fd8aeda32"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("a4970a331a78dc09c418c271e3a41d5d"), aes.getNthRoundKey(12));
}

TEST(Aes256Test, keySchedule1) {
    ByteBuffer key;
    key += HexString("0000000000000000000000000000000000000000000000000000000000000000");
    Aes aes(Aes::Aes256, std::move(key));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("00000000000000000000000000000000"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("aafbfbfbaafbfbfbaafbfbfbaafbfbfb"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("6f6c6ccf0d0f0fac6f6c6ccf0d0f0fac"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("7d8d8d6ad77676917d8d8d6ad7767691"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("5354edc15e5be26d31378ea23c38810e"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("968a81c141fcf7503c717a3aeb070cab"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("9eaa8f28c0f16d45f1c6e3e7cdfe62e9"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("2b312bdf6acddc8f56bca6b5bdbbaa1e"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("6406fd52a4f79017553173f098cf1119"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("6dbba90b0776758451cad331ec71792f"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("e7b0e89c4347788b16760b7b8eb91a62"), aes.getNthRoundKey(12));
    EXPECT_EQ(HexString("74ed0ba1739b7e252251ad14ce20d43b"), aes.getNthRoundKey(13));
    EXPECT_EQ(HexString("10f80a1753bf729c45c979e7cb706385"), aes.getNthRoundKey(14));
}

TEST(Aes256Test, keySchedule2) {
    ByteBuffer key;
    key += HexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    Aes aes(Aes::Aes256, std::move(key));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("0fb8b8b8f04747470fb8b8b8f0474747"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("4a4949655d5f5f73b5b6b69aa2a0a08c"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("355858dcc51f1f9bcaa7a7233ae0e064"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("afa80ae5f2f755964741e30ce5e14380"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("eca0421129bf5d8ae318faa9d9f81acd"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("e60ab7d014fde24653bc014ab65d42ca"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("a2ec6e658b5333ef684bc946b1b3d38b"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("9b6c8a188f91685edc2d69146a702bde"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("a0bd9f782beeac9743a565d1f216b65a"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("fc22349173b35ccfaf9e35dbc5ee1e05"), aes.getNthRoundKey(12));
    EXPECT_EQ(HexString("0695ed132d7b41846ede24559cc8920f"), aes.getNthRoundKey(13));
    EXPECT_EQ(HexString("546d424f27de1e8088402b5b4dae355e"), aes.getNthRoundKey(14));
}

TEST(Aes256Test, keySchedule3) {
    ByteBuffer key;
    key += HexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Aes aes(Aes::Aes256, std::move(key));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), aes.getNthRoundKey(0));
    EXPECT_EQ(HexString("101112131415161718191a1b1c1d1e1f"), aes.getNthRoundKey(1));
    EXPECT_EQ(HexString("a573c29fa176c498a97fce93a572c09c"), aes.getNthRoundKey(2));
    EXPECT_EQ(HexString("1651a8cd0244beda1a5da4c10640bade"), aes.getNthRoundKey(3));
    EXPECT_EQ(HexString("ae87dff00ff11b68a68ed5fb03fc1567"), aes.getNthRoundKey(4));
    EXPECT_EQ(HexString("6de1f1486fa54f9275f8eb5373b8518d"), aes.getNthRoundKey(5));
    EXPECT_EQ(HexString("c656827fc9a799176f294cec6cd5598b"), aes.getNthRoundKey(6));
    EXPECT_EQ(HexString("3de23a75524775e727bf9eb45407cf39"), aes.getNthRoundKey(7));
    EXPECT_EQ(HexString("0bdc905fc27b0948ad5245a4c1871c2f"), aes.getNthRoundKey(8));
    EXPECT_EQ(HexString("45f5a66017b2d387300d4d33640a820a"), aes.getNthRoundKey(9));
    EXPECT_EQ(HexString("7ccff71cbeb4fe5413e6bbf0d261a7df"), aes.getNthRoundKey(10));
    EXPECT_EQ(HexString("f01afafee7a82979d7a5644ab3afe640"), aes.getNthRoundKey(11));
    EXPECT_EQ(HexString("2541fe719bf500258813bbd55a721c0a"), aes.getNthRoundKey(12));
    EXPECT_EQ(HexString("4e5a6699a9f24fe07e572baacdf8cdea"), aes.getNthRoundKey(13));
    EXPECT_EQ(HexString("24fc79ccbf0979e9371ac23c6d68de36"), aes.getNthRoundKey(14));
}

TEST(Aes128Test, encrypt1) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("3ad77bb40d7a3660a89ecaf32466ef97"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, encrypt2) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("f5d3d58503b9699de785895a96fdbaaf"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, encrypt3) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("43b1cd7f598ece23881b00e3ed030688"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, encrypt4) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("7b0c785e27e8ad3f8223207104725dd4"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, encrypt1) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("bd334f1d6e45f25ff712a214571fa5cc"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, encrypt2) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("974104846d0ad3ad7734ecb3ecee4eef"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, encrypt3) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("ef7afd2270e2e60adce0ba2face6444e"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, encrypt4) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("9a4b41ba738d6c72fb16691603c18e0e"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, encrypt1) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("6bc1bee22e409f96e93d7e117393172a");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("f3eed1bdb5d2a03c064b5a7e3db181f8"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, encrypt2) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("591ccb10d410ed26dc5ba74a31362870"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, encrypt3) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("30c81c46a35ce411e5fbc1191a0a52ef");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("b6ed21b99ca6f4f9f153e7b1beafed1d"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, encrypt4) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("f69f2445df4f9b17ad2b417be66c3710");

    aes.encryptBlock(buffer);
    EXPECT_EQ(HexString("23304b7a39f9f3ff067d8d8f9e24ecc7"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, decrypt1) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("3ad77bb40d7a3660a89ecaf32466ef97");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, decrypt2) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("f5d3d58503b9699de785895a96fdbaaf");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, decrypt3) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("43b1cd7f598ece23881b00e3ed030688");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(buffer)));
}

TEST(Aes128Test, decrypt4) {
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    Aes aes(Aes::Aes128, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("7b0c785e27e8ad3f8223207104725dd4");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, decrypt1) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("bd334f1d6e45f25ff712a214571fa5cc");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, decrypt2) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("974104846d0ad3ad7734ecb3ecee4eef");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, decrypt3) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("ef7afd2270e2e60adce0ba2face6444e");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(buffer)));
}

TEST(Aes192Test, decrypt4) {
    ByteBuffer key;
    key += HexString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    Aes aes(Aes::Aes192, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("9a4b41ba738d6c72fb16691603c18e0e");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, decrypt1) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("f3eed1bdb5d2a03c064b5a7e3db181f8");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("6bc1bee22e409f96e93d7e117393172a"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, decrypt2) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("591ccb10d410ed26dc5ba74a31362870");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("ae2d8a571e03ac9c9eb76fac45af8e51"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, decrypt3) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("b6ed21b99ca6f4f9f153e7b1beafed1d");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("30c81c46a35ce411e5fbc1191a0a52ef"), HexString(Hex::encode(buffer)));
}

TEST(Aes256Test, decrypt4) {
    ByteBuffer key;
    key += HexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    Aes aes(Aes::Aes256, std::move(key));

    ByteBuffer buffer;
    buffer += HexString("23304b7a39f9f3ff067d8d8f9e24ecc7");

    aes.decryptBlock(buffer);
    EXPECT_EQ(HexString("f69f2445df4f9b17ad2b417be66c3710"), HexString(Hex::encode(buffer)));
}

} // namespace crypto
