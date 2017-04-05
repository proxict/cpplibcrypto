#ifndef PADDING_PADDING_H_
#define PADDING_PADDING_H_

#include "common/ByteBuffer.h"

namespace crypto {

class Padding {
public:
    virtual ByteBuffer pad(const ByteBuffer&, const std::size_t) const = 0;
};

} // namespace crypto

#endif

