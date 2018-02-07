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

    /// Constructs the allocator with the given wipe flag
    ///
    /// For more information about the wipe flag, see \ref setWipe()
    SecureAllocator(const bool wipe = false) : mWipe(wipe) {}

    SecureAllocator& operator=(SecureAllocator&& other) {
        mWipe = std::move(other.mWipe);
        return *this;
    }

    SecureAllocator(SecureAllocator&& other) { *this = std::move(other); }

    ~SecureAllocator() = default;

    /// Sets the wipe flag to the allocator
    ///
    /// Wipe flag means that on destruction and reallocation the data will not only be destroyed but also memset with a
    /// random bytes.
    void setWipe(const bool wipe) { mWipe = wipe; }

    /// Tells whether or not tht wipe flag is set
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

    /// Constructs an element range in-place the given memory
    ///
    /// Does not allocate any memory. Calls copy constructor of the type specified.
    void constructRange(Pointer first, Pointer last, ConstPointer with) {
        memory::constructRange<ValueType>(first, last, with);
    }

    void destroy(Pointer ptr) {
        memory::destroy(*ptr);
        if (mWipe) {
            wipe(ptr);
        }
    }

    /// Destructs range of elements
    ///
    /// Does not free any memory, only calls destructor
    void destroy(Pointer first, Pointer last) {
        for (Pointer it = first; it != last; ++it) {
            destroy(it);
        }
    }

    void destroy(Reference ref) {
        memory::destroy(ref);
        if (mWipe) {
            wipe(&ref);
        }
    }

    /// Wipes the value at the given pointer
    ///
    /// The memory can be set to a random byte sequence
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
