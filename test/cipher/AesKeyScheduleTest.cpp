#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"
#include "common/DynamicBuffer.h"
#include "common/HexString.h"

namespace crypto {

class AesKeyScheduleTest : public testing::Test, public Aes {
public:
    AesKeyScheduleTest() = default;
    virtual ~AesKeyScheduleTest() = default;

    ByteBuffer getNthRoundKey(const Size index) const {
        ByteBuffer roundKey;
        for (Size i = 0; i < getBlockSize(); ++i) {
            roundKey += m_roundKeys[i + getBlockSize() * index];
        }

        return roundKey;
    }
};

TEST_F(AesKeyScheduleTest, aes128test1) {
    setKey(AesKey(HexString("00000000000000000000000000000000")));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), getNthRoundKey(0));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), getNthRoundKey(1));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"), getNthRoundKey(2));
    EXPECT_EQ(HexString("90973450696ccffaf2f457330b0fac99"), getNthRoundKey(3));
    EXPECT_EQ(HexString("ee06da7b876a1581759e42b27e91ee2b"), getNthRoundKey(4));
    EXPECT_EQ(HexString("7f2e2b88f8443e098dda7cbbf34b9290"), getNthRoundKey(5));
    EXPECT_EQ(HexString("ec614b851425758c99ff09376ab49ba7"), getNthRoundKey(6));
    EXPECT_EQ(HexString("217517873550620bacaf6b3cc61bf09b"), getNthRoundKey(7));
    EXPECT_EQ(HexString("0ef903333ba9613897060a04511dfa9f"), getNthRoundKey(8));
    EXPECT_EQ(HexString("b1d4d8e28a7db9da1d7bb3de4c664941"), getNthRoundKey(9));
    EXPECT_EQ(HexString("b4ef5bcb3e92e21123e951cf6f8f188e"), getNthRoundKey(10));
}

TEST_F(AesKeyScheduleTest, aes128test2) {
    setKey(AesKey(HexString("ffffffffffffffffffffffffffffffff")));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), getNthRoundKey(0));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), getNthRoundKey(1));
    EXPECT_EQ(HexString("adaeae19bab8b80f525151e6454747f0"), getNthRoundKey(2));
    EXPECT_EQ(HexString("090e2277b3b69a78e1e7cb9ea4a08c6e"), getNthRoundKey(3));
    EXPECT_EQ(HexString("e16abd3e52dc2746b33becd8179b60b6"), getNthRoundKey(4));
    EXPECT_EQ(HexString("e5baf3ceb766d488045d385013c658e6"), getNthRoundKey(5));
    EXPECT_EQ(HexString("71d07db3c6b6a93bc2eb916bd12dc98d"), getNthRoundKey(6));
    EXPECT_EQ(HexString("e90d208d2fbb89b6ed5018dd3c7dd150"), getNthRoundKey(7));
    EXPECT_EQ(HexString("96337366b988fad054d8e20d68a5335d"), getNthRoundKey(8));
    EXPECT_EQ(HexString("8bf03f233278c5f366a027fe0e0514a3"), getNthRoundKey(9));
    EXPECT_EQ(HexString("d60a3588e472f07b82d2d7858cd7c326"), getNthRoundKey(10));
}

TEST_F(AesKeyScheduleTest, aes128test3) {
    setKey(AesKey(HexString("000102030405060708090a0b0c0d0e0f")));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), getNthRoundKey(0));
    EXPECT_EQ(HexString("d6aa74fdd2af72fadaa678f1d6ab76fe"), getNthRoundKey(1));
    EXPECT_EQ(HexString("b692cf0b643dbdf1be9bc5006830b3fe"), getNthRoundKey(2));
    EXPECT_EQ(HexString("b6ff744ed2c2c9bf6c590cbf0469bf41"), getNthRoundKey(3));
    EXPECT_EQ(HexString("47f7f7bc95353e03f96c32bcfd058dfd"), getNthRoundKey(4));
    EXPECT_EQ(HexString("3caaa3e8a99f9deb50f3af57adf622aa"), getNthRoundKey(5));
    EXPECT_EQ(HexString("5e390f7df7a69296a7553dc10aa31f6b"), getNthRoundKey(6));
    EXPECT_EQ(HexString("14f9701ae35fe28c440adf4d4ea9c026"), getNthRoundKey(7));
    EXPECT_EQ(HexString("47438735a41c65b9e016baf4aebf7ad2"), getNthRoundKey(8));
    EXPECT_EQ(HexString("549932d1f08557681093ed9cbe2c974e"), getNthRoundKey(9));
    EXPECT_EQ(HexString("13111d7fe3944a17f307a78b4d2b30c5"), getNthRoundKey(10));
}

TEST_F(AesKeyScheduleTest, aes192test1) {
    setKey(AesKey(HexString("000000000000000000000000000000000000000000000000")));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), getNthRoundKey(0));
    EXPECT_EQ(HexString("00000000000000006263636362636363"), getNthRoundKey(1));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), getNthRoundKey(2));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa9b9898c9f9fbfbaa"), getNthRoundKey(3));
    EXPECT_EQ(HexString("9b9898c9f9fbfbaa90973450696ccffa"), getNthRoundKey(4));
    EXPECT_EQ(HexString("f2f457330b0fac9990973450696ccffa"), getNthRoundKey(5));
    EXPECT_EQ(HexString("c81d19a9a171d65353858160588a2df9"), getNthRoundKey(6));
    EXPECT_EQ(HexString("c81d19a9a171d6537bebf49bda9a22c8"), getNthRoundKey(7));
    EXPECT_EQ(HexString("891fa3a8d1958e51198897f8b8f941ab"), getNthRoundKey(8));
    EXPECT_EQ(HexString("c26896f718f2b43f91ed1797407899c6"), getNthRoundKey(9));
    EXPECT_EQ(HexString("59f00e3ee1094f9583ecbc0f9b1e0830"), getNthRoundKey(10));
    EXPECT_EQ(HexString("0af31fa74a8b8661137b885ff272c7ca"), getNthRoundKey(11));
    EXPECT_EQ(HexString("432ac886d834c0b6d2c7df11984c5970"), getNthRoundKey(12));
}

TEST_F(AesKeyScheduleTest, aes192test2) {
    setKey(AesKey(HexString("ffffffffffffffffffffffffffffffffffffffffffffffff")));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), getNthRoundKey(0));
    EXPECT_EQ(HexString("ffffffffffffffffe8e9e9e917161616"), getNthRoundKey(1));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), getNthRoundKey(2));
    EXPECT_EQ(HexString("adaeae19bab8b80f525151e6454747f0"), getNthRoundKey(3));
    EXPECT_EQ(HexString("adaeae19bab8b80fc5c2d8ed7f7a60e2"), getNthRoundKey(4));
    EXPECT_EQ(HexString("2d2b3104686c76f4c5c2d8ed7f7a60e2"), getNthRoundKey(5));
    EXPECT_EQ(HexString("1712403f686820dd454311d92d2f672d"), getNthRoundKey(6));
    EXPECT_EQ(HexString("e8edbfc09797df228f8cd3b7e7e4f36a"), getNthRoundKey(7));
    EXPECT_EQ(HexString("a2a7e2b38f88859e67653a5ef0f2e57c"), getNthRoundKey(8));
    EXPECT_EQ(HexString("2655c33bc1b130516316d2e2ec9e577c"), getNthRoundKey(9));
    EXPECT_EQ(HexString("8bfb6d227b09885e67919b1aa620ab4b"), getNthRoundKey(10));
    EXPECT_EQ(HexString("c53679a929a82ed5a25343f7d95acba9"), getNthRoundKey(11));
    EXPECT_EQ(HexString("598e482fffaee3643a989acd1330b418"), getNthRoundKey(12));
}

TEST_F(AesKeyScheduleTest, aes192test3) {
    setKey(AesKey(HexString("000102030405060708090a0b0c0d0e0f1011121314151617")));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), getNthRoundKey(0));
    EXPECT_EQ(HexString("10111213141516175846f2f95c43f4fe"), getNthRoundKey(1));
    EXPECT_EQ(HexString("544afef55847f0fa4856e2e95c43f4fe"), getNthRoundKey(2));
    EXPECT_EQ(HexString("40f949b31cbabd4d48f043b810b7b342"), getNthRoundKey(3));
    EXPECT_EQ(HexString("58e151ab04a2a5557effb5416245080c"), getNthRoundKey(4));
    EXPECT_EQ(HexString("2ab54bb43a02f8f662e3a95d66410c08"), getNthRoundKey(5));
    EXPECT_EQ(HexString("f501857297448d7ebdf1c6ca87f33e3c"), getNthRoundKey(6));
    EXPECT_EQ(HexString("e510976183519b6934157c9ea351f1e0"), getNthRoundKey(7));
    EXPECT_EQ(HexString("1ea0372a995309167c439e77ff12051e"), getNthRoundKey(8));
    EXPECT_EQ(HexString("dd7e0e887e2fff68608fc842f9dcc154"), getNthRoundKey(9));
    EXPECT_EQ(HexString("859f5f237a8d5a3dc0c02952beefd63a"), getNthRoundKey(10));
    EXPECT_EQ(HexString("de601e7827bcdf2ca223800fd8aeda32"), getNthRoundKey(11));
    EXPECT_EQ(HexString("a4970a331a78dc09c418c271e3a41d5d"), getNthRoundKey(12));
}

TEST_F(AesKeyScheduleTest, aes256test1) {
    setKey(AesKey(HexString("0000000000000000000000000000000000000000000000000000000000000000")));

    EXPECT_EQ(HexString("00000000000000000000000000000000"), getNthRoundKey(0));
    EXPECT_EQ(HexString("00000000000000000000000000000000"), getNthRoundKey(1));
    EXPECT_EQ(HexString("62636363626363636263636362636363"), getNthRoundKey(2));
    EXPECT_EQ(HexString("aafbfbfbaafbfbfbaafbfbfbaafbfbfb"), getNthRoundKey(3));
    EXPECT_EQ(HexString("6f6c6ccf0d0f0fac6f6c6ccf0d0f0fac"), getNthRoundKey(4));
    EXPECT_EQ(HexString("7d8d8d6ad77676917d8d8d6ad7767691"), getNthRoundKey(5));
    EXPECT_EQ(HexString("5354edc15e5be26d31378ea23c38810e"), getNthRoundKey(6));
    EXPECT_EQ(HexString("968a81c141fcf7503c717a3aeb070cab"), getNthRoundKey(7));
    EXPECT_EQ(HexString("9eaa8f28c0f16d45f1c6e3e7cdfe62e9"), getNthRoundKey(8));
    EXPECT_EQ(HexString("2b312bdf6acddc8f56bca6b5bdbbaa1e"), getNthRoundKey(9));
    EXPECT_EQ(HexString("6406fd52a4f79017553173f098cf1119"), getNthRoundKey(10));
    EXPECT_EQ(HexString("6dbba90b0776758451cad331ec71792f"), getNthRoundKey(11));
    EXPECT_EQ(HexString("e7b0e89c4347788b16760b7b8eb91a62"), getNthRoundKey(12));
    EXPECT_EQ(HexString("74ed0ba1739b7e252251ad14ce20d43b"), getNthRoundKey(13));
    EXPECT_EQ(HexString("10f80a1753bf729c45c979e7cb706385"), getNthRoundKey(14));
}

TEST_F(AesKeyScheduleTest, aes256test2) {
    setKey(AesKey(HexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")));

    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), getNthRoundKey(0));
    EXPECT_EQ(HexString("ffffffffffffffffffffffffffffffff"), getNthRoundKey(1));
    EXPECT_EQ(HexString("e8e9e9e917161616e8e9e9e917161616"), getNthRoundKey(2));
    EXPECT_EQ(HexString("0fb8b8b8f04747470fb8b8b8f0474747"), getNthRoundKey(3));
    EXPECT_EQ(HexString("4a4949655d5f5f73b5b6b69aa2a0a08c"), getNthRoundKey(4));
    EXPECT_EQ(HexString("355858dcc51f1f9bcaa7a7233ae0e064"), getNthRoundKey(5));
    EXPECT_EQ(HexString("afa80ae5f2f755964741e30ce5e14380"), getNthRoundKey(6));
    EXPECT_EQ(HexString("eca0421129bf5d8ae318faa9d9f81acd"), getNthRoundKey(7));
    EXPECT_EQ(HexString("e60ab7d014fde24653bc014ab65d42ca"), getNthRoundKey(8));
    EXPECT_EQ(HexString("a2ec6e658b5333ef684bc946b1b3d38b"), getNthRoundKey(9));
    EXPECT_EQ(HexString("9b6c8a188f91685edc2d69146a702bde"), getNthRoundKey(10));
    EXPECT_EQ(HexString("a0bd9f782beeac9743a565d1f216b65a"), getNthRoundKey(11));
    EXPECT_EQ(HexString("fc22349173b35ccfaf9e35dbc5ee1e05"), getNthRoundKey(12));
    EXPECT_EQ(HexString("0695ed132d7b41846ede24559cc8920f"), getNthRoundKey(13));
    EXPECT_EQ(HexString("546d424f27de1e8088402b5b4dae355e"), getNthRoundKey(14));
}

TEST_F(AesKeyScheduleTest, aes256test3) {
    setKey(AesKey(HexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

    EXPECT_EQ(HexString("000102030405060708090a0b0c0d0e0f"), getNthRoundKey(0));
    EXPECT_EQ(HexString("101112131415161718191a1b1c1d1e1f"), getNthRoundKey(1));
    EXPECT_EQ(HexString("a573c29fa176c498a97fce93a572c09c"), getNthRoundKey(2));
    EXPECT_EQ(HexString("1651a8cd0244beda1a5da4c10640bade"), getNthRoundKey(3));
    EXPECT_EQ(HexString("ae87dff00ff11b68a68ed5fb03fc1567"), getNthRoundKey(4));
    EXPECT_EQ(HexString("6de1f1486fa54f9275f8eb5373b8518d"), getNthRoundKey(5));
    EXPECT_EQ(HexString("c656827fc9a799176f294cec6cd5598b"), getNthRoundKey(6));
    EXPECT_EQ(HexString("3de23a75524775e727bf9eb45407cf39"), getNthRoundKey(7));
    EXPECT_EQ(HexString("0bdc905fc27b0948ad5245a4c1871c2f"), getNthRoundKey(8));
    EXPECT_EQ(HexString("45f5a66017b2d387300d4d33640a820a"), getNthRoundKey(9));
    EXPECT_EQ(HexString("7ccff71cbeb4fe5413e6bbf0d261a7df"), getNthRoundKey(10));
    EXPECT_EQ(HexString("f01afafee7a82979d7a5644ab3afe640"), getNthRoundKey(11));
    EXPECT_EQ(HexString("2541fe719bf500258813bbd55a721c0a"), getNthRoundKey(12));
    EXPECT_EQ(HexString("4e5a6699a9f24fe07e572baacdf8cdea"), getNthRoundKey(13));
    EXPECT_EQ(HexString("24fc79ccbf0979e9371ac23c6d68de36"), getNthRoundKey(14));
}

} // namespace crypto
