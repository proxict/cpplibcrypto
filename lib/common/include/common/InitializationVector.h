#ifndef COMMON_INITIALIZATIONVECTOR_H_
#define COMMON_INITIALIZATIONVECTOR_H_

#include <cstddef>

#include "common/common.h"
#include "common/LinearIterator.h"

namespace crypto {

class InitializationVector {
public:
    using ValueType = Byte;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
    using RValuetReference = ValueType&&;
    using Pointer = ValueType*;
    using ConstPointer = const ValueType*;
    using Iterator = LinearIterator<ValueType>;
    using ConstIterator = LinearIterator<const ValueType>;

    InitializationVector() = default;

    virtual bool isValid(const Size) const = 0;

    virtual Size size() const = 0;

    virtual void reset() = 0;

    virtual void setNew(const ConstIterator begin) = 0;

    virtual ConstReference at(const Size index) const = 0;

    virtual ConstReference operator[](const Size index) const = 0;

    virtual ConstPointer data() const = 0;

    ConstIterator begin() const { return cbegin(); }

    ConstIterator end() const { return cend(); }

    ConstIterator cbegin() const { return ConstIterator(data()); }

    ConstIterator cend() const { return ConstIterator(data(), size()); }
};

} // namespace crypto

#endif
