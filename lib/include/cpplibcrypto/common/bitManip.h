#ifndef CPPLIBCRYPTO_COMMON_BITMANIP_H_
#define CPPLIBCRYPTO_COMMON_BITMANIP_H_

#include "cpplibcrypto/common/common.h"

NAMESPACE_CRYPTO_BEGIN

namespace bits {

/// Rotates bits to the left by the given amount of bits
///
/// \param value The value whose bit will get rotated
/// \param bits The number of bits to rotate
/// \returns The rotated value
template <typename T>
inline T rotateLeft(const T value, const Byte bits) {
    return (value << bits) | (value >> (8 * sizeof(T) - bits));
}

} // namespace bits

NAMESPACE_CRYPTO_END

#endif // CPPLIBCRYPTO_COMMON_BITMANIP_H_
