#ifndef CPPLIBCRYPTO_BUFFER_UTILS_SECUREALLOCATOR_H_
#define CPPLIBCRYPTO_BUFFER_UTILS_SECUREALLOCATOR_H_

#include "cpplibcrypto/common/Memory.h"
#include "cpplibcrypto/common/common.h"

#include <limits>
#include <memory>

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
    constexpr SecureAllocator(const bool wipe = true)
        : mWipe(wipe) {}

    SecureAllocator& operator=(SecureAllocator&& other) {
        mWipe = std::move(other.mWipe);
        return *this;
    }

    constexpr SecureAllocator(SecureAllocator&& other) { *this = std::move(other); }

    ~SecureAllocator() = default;

    /// Sets the wipe flag to the allocator
    ///
    /// Wipe flag means that on destruction and reallocation the data will not only be destroyed but also
    /// memset with a random bytes.
    constexpr void setWipe(const bool wipe) { mWipe = wipe; }

    /// Tells whether or not tht wipe flag is set
    constexpr bool isWipe() const { return mWipe; }

    template <class T2>
    constexpr SecureAllocator(const SecureAllocator<T2>& other)
        : mWipe(other.mWipe) {}

    constexpr SecureAllocator(const SecureAllocator& other)
        : mWipe(other.mWipe) {}

    constexpr Pointer address(Reference ref) { return &ref; }

    constexpr ConstPointer address(ConstReference ref) { return &ref; }

    constexpr SizeType max_size() const { return std::numeric_limits<SizeType>::max() / sizeof(ValueType); }

    constexpr SizeType maxSize() const { return max_size(); };

    constexpr Pointer allocate(const SizeType count, const void* = 0) {
        return memory::allocate<ValueType>(count);
    }

    void deallocate(Pointer ptr, const SizeType) { memory::deallocate(ptr); }

    template <typename... TArgs>
    constexpr void construct(Pointer ptr, TArgs&&... value) {
        memory::construct<ValueType>(ptr, std::forward<TArgs>(value)...);
    }

    /// Constructs an element range in-place the given memory
    ///
    /// Does not allocate any memory. Calls copy constructor of the type specified.
    constexpr void constructRange(Pointer first, Pointer last, ConstPointer with) {
        memory::constructRange<ValueType>(first, last, with);
    }

    constexpr void destroy(Reference ref) {
        memory::destroy(ref);
        if (mWipe) {
            memory::wipe<ValueType>(&ref);
        }
    }

    constexpr void destroy(Pointer ptr) { memory::destroy(*ptr); }

    /// Destructs range of elements
    ///
    /// Does not free any memory, only calls destructor
    constexpr void destroy(Pointer first, Pointer last) {
        for (Pointer it = first; it != last; ++it) {
            destroy(it);
        }
    }

    template <class T2>
    constexpr bool operator==(SecureAllocator<T2> const&) const {
        return true;
    }

    template <class T2>
    constexpr bool operator!=(SecureAllocator<T2> const&) const {
        return false;
    }

protected:
    bool mWipe;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_BUFFER_UTILS_SECUREALLOCATOR_H_
