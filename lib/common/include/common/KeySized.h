#ifndef COMMON_KEYSIZED_H_
#define COMMON_KEYSIZED_H_

#include "common/Key.h"

#include <cstddef>

#include "common/ByteBuffer.h"

namespace crypto {

template<Size TMinKeySize, Size TMaxKeySize = 0, Size TMod = 1>
class KeySized : public Key {
public:
    bool isValid(const Size keySize) const override {
        return ((keySize >= getMin()) && (keySize <= getMax()) && (keySize % getMod() == 0));
    }

    static constexpr Size getMin() {
        return TMinKeySize;
    }

    static constexpr Size getMax() {
        return TMaxKeySize > 0 ? TMaxKeySize : TMinKeySize;
    }

    static constexpr Size getMod() {
        return TMod;
    }

protected:
    KeySized() = default;
};

} // namespace crypto

#endif
