#include <memory>

#include "gtest/gtest.h"

#include "cipher/Aes.h"

namespace crypto {

TEST(AesTest, basic) {
    CbcCipher<Aes<AesKeySize::Aes128>, Pkcs7>::encrypt({0, 0});
    EcbCipher<Aes<AesKeySize::Aes256>, Pkcs7>::encrypt({0, 0});
    CbcCipher<Rc5<1024, Rc5BlockSize::Rc564, 12>, Pkcs7>::encrypt({0, 0});

    ByteBuffer key{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ByteBuffer iv{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ByteBuffer data{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CbcCipher<Aes<AesKeySize::Aes128>, Pkcs7> aesCbc;
    aesCbc.init(key, iv);
    ByteBuffer encrypted;
    encrypted += aesCbc.update(data);
    encrypted += aesCbc.finish();
}

} // namespace crypto
