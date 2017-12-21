#ifndef CIPHER_AESKEY_H_
#define CIPHER_AESKEY_H_

#include "common/KeySized.h"

#include <memory>

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/HexString.h"

namespace crypto {

class AesKey : public KeySized<16, 32, 8> {
public:
    AesKey() : KeySized() {}

    AesKey(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key = std::move(key);
    }

    AesKey(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key += key;
    }

    Size size() const override {
        return m_key.size();
    }

    const ByteBuffer& getBytes() const override {
        return m_key;
    }

private:
    AesKey& operator=(const AesKey&) = delete;
    AesKey(const AesKey&) = delete;
    AesKey& operator=(AesKey&&) = delete;
    AesKey(AesKey&&) = delete;

    ByteBuffer m_key;
};

} // namespace crypto

#endif
