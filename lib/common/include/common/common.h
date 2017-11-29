//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines common definitions and types used across the library
///
//------------------------------------------------------------------------------
#ifndef COMMON_COMMON_H_
#define COMMON_COMMON_H_

#include <cstdint>
#include <cassert>

namespace crypto {

using Byte = uint8_t;
using Size = std::size_t;

#define ASSERT(x) assert(x)

} // namespace crypto

#endif

