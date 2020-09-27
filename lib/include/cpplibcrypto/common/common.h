#ifndef CPPLIBCRYPTO_COMMON_COMMON_H_
#define CPPLIBCRYPTO_COMMON_COMMON_H_

#include <cassert>
#include <cstdint>

#define ASSERT(x) assert(x)

namespace crypto {

using Byte = uint8_t;
using Size = std::size_t;
using Dword = uint32_t;
using Qword = uint64_t;

} // namespace crypto

#endif
