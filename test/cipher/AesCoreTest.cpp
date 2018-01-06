#include <memory>

#include "gtest/gtest.h"

#include "cipher/AesCore.h"
#include "common/DynamicBuffer.h"
#include "common/HexString.h"

namespace crypto {

using ByteBufferView = BufferView<Byte>;

TEST(AesCoreTest, subBytes) {
    StaticBuffer<Byte, 16> buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    ByteBufferView view(buffer);
    AesCore::subBytes(view);
    AesCore::subBytesInv(view);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

TEST(AesCoreTest, shiftRows) {
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

    StaticBuffer<Byte, 16> buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    ByteBufferView view(buffer);
    AesCore::shiftRows(view);
    EXPECT_EQ(HexString("00050A0F04090E03080D02070C01060B"), buffer);
    AesCore::shiftRowsInv(view);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

TEST(AesCoreTest, mixColumns) {
    StaticBuffer<Byte, 16> buffer;
    buffer += HexString("000102030405060708090A0B0C0D0E0F");
    ByteBufferView view(buffer);
    AesCore::mixColumns(view);
    EXPECT_EQ(HexString("02070005060304010a0f080d0e0b0c09"), buffer);
    AesCore::mixColumnsInv(view);
    EXPECT_EQ(HexString("000102030405060708090A0B0C0D0E0F"), buffer);
}

} // namespace crypto
