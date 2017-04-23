#ifndef COMMON_INITIALIZATIONVECTORSIZED_H_
#define COMMON_INITIALIZATIONVECTORSIZED_H_

#include "common/InitializationVector.h"

#include <cstddef>

namespace crypto {

template<std::size_t Size>
class InitializationVectorSized : public InitializationVector {
public:
    bool isValid(const std::size_t size) const override {
        return (size == Size);
    }

protected:
    InitializationVectorSized() = default;
};

} // namespace crypto

#endif
