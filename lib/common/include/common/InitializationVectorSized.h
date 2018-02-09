#ifndef COMMON_INITIALIZATIONVECTORSIZED_H_
#define COMMON_INITIALIZATIONVECTORSIZED_H_

#include "common/InitializationVector.h"

NAMESPACE_CRYPTO_BEGIN

template <Size TSize>
class InitializationVectorSized : public InitializationVector {
public:
    bool isValid(const Size size) const override { return (size == TSize); }

protected:
    InitializationVectorSized() = default;
};

NAMESPACE_CRYPTO_END

#endif
