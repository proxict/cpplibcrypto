#ifndef COMMON_INITIALIZATIONVECTORSIZED_H_
#define COMMON_INITIALIZATIONVECTORSIZED_H_

#include "common/InitializationVector.h"

namespace crypto {

template<Size TSize>
class InitializationVectorSized : public InitializationVector {
public:
    bool isValid(const Size size) const override {
        return (size == TSize);
    }

protected:
    InitializationVectorSized() = default;
};

} // namespace crypto

#endif
