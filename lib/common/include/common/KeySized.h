#ifndef COMMON_KEYSIZED_H_
#define COMMON_KEYSIZED_H_

#include "common/Key.h"

#include <cstddef>

#include "common/DynamicBuffer.h"

namespace crypto {

/// Specifies the restraints for key size
/// \param TMinKeySize Specifies the minimal key size required
/// \param TMaxKeySize Specifies the maximal key size allowed
/// \param TMod Specifies the required divisor of the key size
template<Size TMinKeySize, Size TMaxKeySize = 0, Size TMod = 1>
class KeySized : public Key {
public:
    bool isValid(const Size keySize) const override {
        return ((keySize >= getMin()) && (keySize <= getMax()) && (keySize % getMod() == 0));
    }

    /// Returns the minimal required size of the key
    static constexpr Size getMin() {
        return TMinKeySize;
    }

    /// Returns the maximal allowed size of the key
    static constexpr Size getMax() {
        return TMaxKeySize > 0 ? TMaxKeySize : TMinKeySize;
    }

    /// Returns the required key divisor
    static constexpr Size getMod() {
        return TMod;
    }

protected:
    KeySized() = default;
};

} // namespace crypto

#endif
