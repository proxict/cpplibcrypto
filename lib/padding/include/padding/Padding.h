#ifndef PADDING_PADDING_H_
#define PADDING_PADDING_H_

#include "common/StaticByteBuffer.h"

namespace crypto {

class Padding {
public:
    virtual void pad(StaticByteBufferBase&, const std::size_t) const = 0;

    virtual void unpad(StaticByteBufferBase&) const = 0;
};

class PaddingNone : public Padding {
public:
    virtual void pad(StaticByteBufferBase&, const std::size_t) const override {}

    virtual void unpad(StaticByteBufferBase&) const override {}
};

} // namespace crypto

#endif
