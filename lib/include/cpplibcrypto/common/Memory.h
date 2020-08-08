#ifndef CPPLIBCRYPTO_COMMON_MEMORY_H_
#define CPPLIBCRYPTO_COMMON_MEMORY_H_

#include "cpplibcrypto/common/TypeTraits.h"
#include "cpplibcrypto/common/common.h"

#include <utility>

NAMESPACE_CRYPTO_BEGIN
namespace memory {

/// Allocates memory for the given number of elements
///
/// Does not construct the elements
/// \returns Pointer to the allocated memory
template <typename T>
constexpr inline T* allocate(const Size count) {
    return static_cast<T*>(::operator new(count * sizeof(T)));
}

/// Frees the given memory
///
/// Does not call any destructor
inline void deallocate(void* ptr) {
    ::operator delete(ptr);
}

/// Constructs an element in-place the given memory
///
/// Does not allocate any memory
template <typename T, typename... TArgs>
constexpr inline void construct(void* ptr, TArgs&&... value) {
    new (ptr) T(std::forward<TArgs>(value)...);
}

/// Constructs an element range in-place the given memory
///
/// Does not allocate any memory. Calls copy constructor of the type specified.
template <typename T>
constexpr inline void constructRange(T* first, T* last, const T* source) {
    const T* srcIt = source;
    for (T* it = first; it != last; ++it) {
        construct<T>(it, *(srcIt++));
    }
}

/// Destructs the given object
///
/// Does not free any memory, only calls destructor
template <typename T>
constexpr inline void destroy(T& object) {
    object.~T();
}

/// Destructs an element range
///
/// Does not free any memory, only calls destroctor
template <typename TIterator>
constexpr inline void destroy(TIterator first, TIterator last) {
    for (auto it = first; it != last; ++it) {
        destroy(*it);
    }
}

/// Wipes the memory at the given pointer
///
/// The memory can be set to a random byte sequence
template <typename T>
constexpr void wipe(T* ptr) {
    Byte* bytePtr = reinterpret_cast<Byte*>(ptr);
    for (Size i = 0; i < sizeof(T); ++i) {
        bytePtr[i] = 0;
    }
}

} // namespace memory
NAMESPACE_CRYPTO_END

#endif
