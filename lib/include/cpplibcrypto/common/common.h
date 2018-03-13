#ifndef CPPLIBCRYPTO_COMMON_COMMON_H_
#define CPPLIBCRYPTO_COMMON_COMMON_H_

#include <cassert>
#include <cstdint>

#define NAMESPACE_CRYPTO_BEGIN namespace crypto {
#define NAMESPACE_CRYPTO_END }

#define ASSERT(x) assert(x)

NAMESPACE_CRYPTO_BEGIN

using Byte = uint8_t;
using Size = std::size_t;

NAMESPACE_CRYPTO_END

#endif
