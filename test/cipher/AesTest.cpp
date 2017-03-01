#include <memory>

#include "gtest/gtest.h"

#include "cipher/AES.h"

namespace crypto {

TEST(AesTest, basic) {
    AES<aes_key_size::AES128, cipher_operation_mode::CBC, padding::PKCS7>::encrypt({0, 0});
    AES<aes_key_size::AES128, cipher_operation_mode::CBC, padding::PKCS7>::decrypt({0, 0});
}

TEST(AesTest, exception) {
}

} // namespace crypto
