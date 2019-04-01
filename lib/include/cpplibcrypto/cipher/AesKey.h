#ifndef CPPLIBCRYPTO_CIPHER_AESKEY_H_
#define CPPLIBCRYPTO_CIPHER_AESKEY_H_

#include "cpplibcrypto/common/KeySized.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/HexString.h"
#include "cpplibcrypto/buffer/Password.h"
#include "cpplibcrypto/common/Exception.h"

#include <memory>

NAMESPACE_CRYPTO_BEGIN

/// AES key representation
///
/// Requires the key to be at least 16 and at most 32 bytes in size and to be dividable by 8
class AesKey : public KeySized<16, 32, 8> {
public:
    /// \throws Exception if the key size does not match the requirements
    AesKey(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("AES-Key: Invalid key size passed");
        }
        mKey = std::move(key);
    }

    /// \throws Exception if the key size does not match the requirements
    AesKey(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("AES-Key: Invalid key size passed");
        }
        mKey << key;
    }

    /// \throws Exception if the key size does not match the requirements
    AesKey(const Password& password) {
        if (!isValid(password.size())) {
            throw Exception("AES-Key: Invalid key size passed");
        }
        mKey.insert(mKey.end(), password.begin(), password.end());
    }

    /// Returns the key size in bytes
    Size size() const override { return mKey.size(); }

    /// Returns the byte representation of the key
    const ByteBuffer& getBytes() const override { return mKey; }

private:
    AesKey& operator=(const AesKey&) = delete;
    AesKey(const AesKey&) = delete;
    AesKey& operator=(AesKey&&) = delete;
    AesKey(AesKey&&) = delete;

    ByteBuffer mKey;
};

NAMESPACE_CRYPTO_END

#endif
