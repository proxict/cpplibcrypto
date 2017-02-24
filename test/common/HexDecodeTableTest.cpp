#include "gtest/gtest.h"
#include "common/HexDecodeTable.h"

namespace crypto {

TEST(HexDecodeTableTest, basic) {
    HexDecodeTable table;
    EXPECT_EQ(0U, table.hex2byte('0', '0'));
    EXPECT_EQ(255U, table.hex2byte('f', 'f'));
    EXPECT_EQ(15U, table.hex2byte('0', 'f'));
    EXPECT_EQ(240U, table.hex2byte('f', '0'));
}

TEST(HexDecodeTableTest, exception) {
    HexDecodeTable table;
    EXPECT_THROW(table.hex2byte('0', '/'), std::invalid_argument);
    EXPECT_THROW(table.hex2byte('0', ':'), std::invalid_argument);
    EXPECT_THROW(table.hex2byte('0', '@'), std::invalid_argument);
    EXPECT_THROW(table.hex2byte('0', 'G'), std::invalid_argument);
    EXPECT_THROW(table.hex2byte('0', '`'), std::invalid_argument);
    EXPECT_THROW(table.hex2byte('0', 'g'), std::invalid_argument);
}

} // namespace crypto
