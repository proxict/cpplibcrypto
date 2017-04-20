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

protected:
    KeyParams() = default;
};

} // namespace crypto

#endif

