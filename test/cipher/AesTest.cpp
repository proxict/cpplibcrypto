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

    ByteBuffer shifted;
    shifted += HexString("000102030405060708090A0B0C0D0E0F");
    shiftRows(shifted);
    EXPECT_EQ(HexString("00050A0F04090E03080D02070C01060B"), shifted);
}

// TODO(ProXicT): mixColumns test

TEST(Aes128Test, encrypt1) {
    Aes aes(Aes::Aes256);
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    aes.setKey(std::move(key));
    ByteBuffer data;
    data += HexString("6bc1bee22e409f96e93d7e117393172a");
    ByteBuffer out;
    out += aes.encryptBlock(data);
    EXPECT_EQ(HexString("3ad77bb40d7a3660a89ecaf32466ef97"), HexString(Hex::encode(out)));
}

TEST(Aes128Test, encrypt2) {
    Aes aes(Aes::Aes256);
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    aes.setKey(std::move(key));
    ByteBuffer data;
    data += HexString("ae2d8a571e03ac9c9eb76fac45af8e51");
    ByteBuffer out;
    out += aes.encryptBlock(data);
    EXPECT_EQ(HexString("f5d3d58503b9699de785895a96fdbaaf"), HexString(Hex::encode(out)));
}

TEST(Aes128Test, encrypt3) {
    Aes aes(Aes::Aes256);
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    aes.setKey(std::move(key));
    ByteBuffer data;
    data += HexString("30c81c46a35ce411e5fbc1191a0a52ef");
    ByteBuffer out;
    out += aes.encryptBlock(data);
    EXPECT_EQ(HexString("43b1cd7f598ece23881b00e3ed030688"), HexString(Hex::encode(out)));
}

TEST(Aes128Test, encrypt4) {
    Aes aes(Aes::Aes256);
    ByteBuffer key;
    key += HexString("2b7e151628aed2a6abf7158809cf4f3c");
    aes.setKey(std::move(key));
    ByteBuffer data;
    data += HexString("f69f2445df4f9b17ad2b417be66c3710");
    ByteBuffer out;
    out += aes.encryptBlock(data);
    EXPECT_EQ(HexString("7b0c785e27e8ad3f8223207104725dd4"), HexString(Hex::encode(out)));
}

} // namespace crypto
