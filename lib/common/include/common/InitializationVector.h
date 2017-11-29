#ifndef COMMON_INITIALIZATIONVECTOR_H_
#define COMMON_INITIALIZATIONVECTOR_H_

#include <cstddef>

#include "common/common.h"

namespace crypto {

class InitializationVector {
public:
    InitializationVector() = default;

    virtual bool isValid(const Size) const = 0;

    virtual Size size() const = 0;

    virtual Byte operator[](const Size) const = 0;

    virtual Byte& operator[](const Size) = 0;

    virtual void reset() = 0;
};

} // namespace crypto

#endif
