#include "gtest/gtest.h"
#include "common/HexEncodeTable.h"

namespace crypto {

TEST(HexEncodeTableTest, basic) {
    EXPECT_STREQ("00", HexEncodeTable::byte2char(0U));
    EXPECT_STREQ("ff", HexEncodeTable::byte2char(255U));
    EXPECT_STREQ("0f", HexEncodeTable::byte2char(15U));
    EXPECT_STREQ("f0", HexEncodeTable::byte2char(240U));
}

} // namespace crypto
