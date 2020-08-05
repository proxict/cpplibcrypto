#ifndef CPPLIBCRYPTO_BUFFER_UTILS_BUFFERUTILS_H_
#define CPPLIBCRYPTO_BUFFER_UTILS_BUFFERUTILS_H_

#include "cpplibcrypto/common/common.h"

NAMESPACE_CRYPTO_BEGIN
namespace bufferUtils {

/// Applies an XOR operation on the given container with the given source
///
/// \param buffer Buffer which will get XORed
/// \param xorSource Data with which the given buffer will be XORed
template <typename TBuffer, typename TBufferXor>
constexpr inline void xorBuffer(TBuffer& buffer, const TBufferXor& xorSource) {
    Size index = 0;
    for (typename TBuffer::Reference b : buffer) {
        b ^= xorSource[index++];
    }
}

/// Applies an XOR operation on the given iterator range with the given source
///
/// \param first The beginning of the data to be XORed
/// \param last The end of the data to be XORed
/// \param xorSourceFirst The beginning of the data with which the given range will be XORed
template <typename TIterator, typename TConstIterator>
constexpr inline void xorBuffer(TIterator first, TIterator last, TConstIterator xorSourceFirst) {
    TIterator srcIt = xorSourceFirst;
    for (TIterator it = first; it != last; ++it, ++srcIt) {
        *it ^= *srcIt;
    }
}

/// Pushes an XORed data to the given container
///
/// \param container The container to push to
/// \param first The beginning of the data to be XORed and pushed
/// \param lasat The end of the data to be XORed and pushed
/// \param xorSource The beginning of the data with which the given range will be XORed and pushed
template <typename TBuffer, typename TConstIterator>
constexpr inline void
pushXored(TBuffer& container, TConstIterator first, TConstIterator last, TConstIterator xorSource) {
    TConstIterator xorIt = xorSource;
    for (TConstIterator it = first; it != last; ++it) {
        container.push(*it ^ *xorIt++);
    }
}

template <typename TBuffer1, typename TBuffer2>
constexpr inline bool equal(const TBuffer1& c1, const TBuffer2& c2) {
    if (c1.size() != c2.size()) {
        return false;
    }
    for (Size i = 0; i < c1.size(); ++i) {
        if (c1[i] != c2[i]) {
            return false;
        }
    }
    return true;
}

} // namespace bufferUtils
NAMESPACE_CRYPTO_END

#endif
