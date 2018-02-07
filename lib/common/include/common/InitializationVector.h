#ifndef COMMON_INITIALIZATIONVECTOR_H_
#define COMMON_INITIALIZATIONVECTOR_H_

#include <cstddef>

#include "common/LinearIterator.h"
#include "common/common.h"

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

    /// Tells whether or not the given size is valid for this IV
    virtual bool isValid(const Size) const = 0;

    /// Returns the size of this IV
    virtual Size size() const = 0;

    /// Sets the IV to the initial state
    virtual void reset() = 0;

    /// Sets new IV
    virtual void setNew(const ConstIterator begin) = 0;

    /// Returns a byte at the specified index
    virtual ConstReference at(const Size index) const = 0;

    /// \copydoc at()
    virtual ConstReference operator[](const Size index) const = 0;

    /// Returns a pointer to the beginning of the IV byte sequence
    virtual ConstPointer data() const = 0;

    /// Returns an iterator to the beginning of the IV byte sequence
    ConstIterator begin() const { return cbegin(); }

    /// Returns an iterator to the end of the IV byte sequence
    ConstIterator end() const { return cend(); }

    /// Returns an iterator to the beginning of the IV byte sequence
    ConstIterator cbegin() const { return ConstIterator(data()); }

    /// Returns an iterator to the end of the IV byte sequence
    ConstIterator cend() const { return ConstIterator(data(), size()); }
};

} // namespace crypto

#endif
