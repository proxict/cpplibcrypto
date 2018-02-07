#ifndef CIPHER_AESKEY_H_
#define CIPHER_AESKEY_H_

#include "common/KeySized.h"

#include <memory>

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/HexString.h"

namespace crypto {

/// AES key representation
///
/// Requires the key to be at least 16 and at most 32 bytes in size and to be dividable by 8
class AesKey : public KeySized<16, 32, 8> {
public:
    AesKey() : KeySized() {}

    AesKey(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        mKey = std::move(key);
    }

    AesKey(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        mKey += key;
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

} // namespace crypto

#endif
