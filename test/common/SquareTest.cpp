#include "gtest/gtest.h"
#include "common/Square.h"

namespace crypto {

TEST(SquareTest, basic) {
    EXPECT_EQ(0, square(0));
    EXPECT_EQ(1, square(1));
    EXPECT_EQ(36, square(5));
}

TEST(SquareTest, negative) {
    EXPECT_EQ(1, square(-1));
    EXPECT_EQ(36, square(-6));
}

TEST(SquareTest, limits) {
    EXPECT_EQ(1073676289, square(-32767));
    EXPECT_EQ(1073676289, square(32767));
}

TEST(SquareTest, exception) {
    EXPECT_THROW(square(-32768), IllegalArgumentException);
    EXPECT_THROW(square(0x7fffffff), IllegalArgumentException);
}

} // namespace crypto
