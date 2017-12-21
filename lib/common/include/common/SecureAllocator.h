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
    using value_type = T;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using reference = value_type&;
    using const_reference = const value_type&;
    using size_type = Size;
    using difference_type = std::ptrdiff_t;

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

    pointer address(reference ref) { return &ref; }

    const_pointer address(const_reference ref) { return &ref; }

    size_type max_size() const { return std::numeric_limits<size_type>::max() / sizeof(value_type); }

    pointer allocate(const size_type count, const void* = 0) { return memory::allocate<value_type>(count); }

    void deallocate(pointer ptr, const size_type) { memory::deallocate(ptr); }

    // void construct(pointer ptr, const value_type& value) { memory::construct(ptr, value); }

    template <typename... TArgs>
    void construct(pointer ptr, TArgs&&... value) {
        memory::construct<value_type>(ptr, std::forward<TArgs>(value)...);
    }

    void destroy(pointer ptr) {
        if (mWipe) {
            wipe(ptr);
        }
        memory::destroy(*ptr);
    }

    void destroy(reference ref) {
        if (mWipe) {
            wipe(&ref);
        }
        memory::destroy(ref);
    }

    void wipe(pointer ptr) {
        Byte* bytePtr = reinterpret_cast<Byte*>(ptr);
        for (Size i = 0; i < sizeof(value_type); ++i) {
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
