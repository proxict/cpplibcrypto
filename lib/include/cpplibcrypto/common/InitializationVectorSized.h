#ifndef CPPLIBCRYPTO_COMMON_INITIALIZATIONVECTORSIZED_H_
#define CPPLIBCRYPTO_COMMON_INITIALIZATIONVECTORSIZED_H_

#include "cpplibcrypto/common/InitializationVector.h"

namespace crypto {

template <Size TSize>
class InitializationVectorSized : public InitializationVector {
public:
    bool isValid(const Size size) const override { return (size == TSize); }

    virtual ~InitializationVectorSized() = default;

protected:
    InitializationVectorSized() = default;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_COMMON_INITIALIZATIONVECTORSIZED_H_
