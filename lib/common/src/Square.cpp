//------------------------------------------------------------------------------
///
/// \file
/// \brief Defines a sample function.
///
//------------------------------------------------------------------------------
#include "common/Square.h"

namespace crypto {

int square(int x) {
    if (x >= -32767 && x <= 32767) {
        return x * x;
    }
    throw IllegalArgumentException();
}

} // namespace crypto
