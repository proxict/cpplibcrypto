#ifndef COMMON_SECUREALLOCATOR_H_
#define COMMON_SECUREALLOCATOR_H_

#include <limits>
#include <memory>

#include "common/Memory.h"
#include "common/common.h"

namespace crypto {

template <class T>
class SecureAllocator {
public:
    using ValueType = T;
    using Reference = ValueType&;
    using ConstReference = const ValueType&;
    using Pointer = ValueType*;
    using ConstPointer = const ValueType*;
    using SizeType = Size;
    using DifferenceType = std::ptrdiff_t;

    using value_type = ValueType;
    using reference = Reference;
    using const_reference = ConstReference;
    using pointer = Pointer;
    using const_pointer = ConstPointer;
    using size_type = SizeType;
    using difference_type = DifferenceType;

    template <class TargetT>
    class rebind {
    public:
        using other = SecureAllocator<TargetT>;
    };

    SecureAllocator(const bool sensitive = false) : mWipe(sensitive) {}

    SecureAllocator& operator=(SecureAllocator&& other) {
        mWipe = std::move(other.mWipe);
        return *this;
    }

    SecureAllocator(SecureAllocator&& other) { *this = std::move(other); }

    ~SecureAllocator() = default;

    void setWipe(const bool wipe) { mWipe = wipe; }

    bool isWipe() const { return mWipe; }

    template <class T2>
    SecureAllocator(const SecureAllocator<T2>& other) : mWipe(other.mWipe) {}

    Pointer address(Reference ref) { return &ref; }

    ConstPointer address(ConstReference ref) { return &ref; }

    SizeType max_size() const { return std::numeric_limits<SizeType>::max() / sizeof(ValueType); }

    SizeType maxSize() const { return max_size(); };

    Pointer allocate(const SizeType count, const void* = 0) { return memory::allocate<ValueType>(count); }

    void deallocate(Pointer ptr, const SizeType) { memory::deallocate(ptr); }

    template <typename... TArgs>
    void construct(Pointer ptr, TArgs&&... value) {
        memory::construct<ValueType>(ptr, std::forward<TArgs>(value)...);
    }

    void constructRange(Pointer first, Pointer last, ConstPointer with) {
        memory::constructRange<ValueType>(first, last, with);
    }

    void destroy(Pointer ptr) {
        memory::destroy(*ptr);
        if (mWipe) {
            wipe(ptr);
        }
    }

    void destroy(Reference ref) {
        memory::destroy(ref);
        if (mWipe) {
            wipe(&ref);
        }
    }

    void wipe(Pointer ptr) {
        Byte* bytePtr = reinterpret_cast<Byte*>(ptr);
        for (Size i = 0; i < sizeof(ValueType); ++i) {
            bytePtr[i] = 0;
        }
    }

    template <class T2>
    bool operator==(SecureAllocator<T2> const&) const {
        return true;
    }

    template <class T2>
    bool operator!=(SecureAllocator<T2> const&) const {
        return false;
    }

protected:
    bool mWipe;
};

} // namespace crypto

#endif
