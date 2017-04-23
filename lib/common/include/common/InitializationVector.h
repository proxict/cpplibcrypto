#ifndef COMMON_INITIALIZATIONVECTOR_H_
#define COMMON_INITIALIZATIONVECTOR_H_

#include <cstddef>

#include "common/common.h"

namespace crypto {

class InitializationVector {
public:
    InitializationVector() = default;

    virtual bool isValid(const std::size_t) const = 0;

    virtual std::size_t size() const = 0;

    virtual byte operator[](const std::size_t) const = 0;

    virtual byte& operator[](const std::size_t) = 0;

    virtual void reset() = 0;
};

} // namespace crypto

#endif
