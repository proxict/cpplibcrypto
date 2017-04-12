#ifndef COMMON_KEYPARAMS_H_
#define COMMON_KEYPARAMS_H_

#include "common/Key.h"

#include <memory>

#include "common/ByteBuffer.h"
#include "common/Exception.h"
#include "common/HexString.h"

namespace crypto {

template<std::size_t minKeySize, std::size_t maxKeySize = 0, std::size_t mod = 1>
class KeyParams : public Key {
public:
    KeyParams() = default;

    KeyParams(ByteBuffer&& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key = std::move(key);
    }

    KeyParams(const HexString& key) {
        if (!isValid(key.size())) {
            throw Exception("Invalid key size passed");
        }
        m_key += key;
    }
    
    KeyParams& operator=(KeyParams&& other) {
        m_key = std::move(other.m_key);
        return *this;
    }

    KeyParams(KeyParams&& other) {
        *this = std::move(other);
    }

    std::size_t size() const override {
        return m_key.size();
    }

    const ByteBuffer& getKeyBytes() const override {
        return m_key;
    }

    bool isValid(const std::size_t keySize) const override {
        return ((keySize >= getMin()) && (keySize <= getMax()) && (keySize % getMod() == 0));
    }

    static constexpr std::size_t getMin() {
        return minKeySize;
    }

    static constexpr std::size_t getMax() {
        return maxKeySize > 0 ? maxKeySize : minKeySize;
    }

    static constexpr std::size_t getMod() {
        return mod;
    }

private:
    KeyParams(const KeyParams&) = delete;
    KeyParams& operator=(const KeyParams&) = delete;

    ByteBuffer m_key;
};

} // namespace crypto

#endif

