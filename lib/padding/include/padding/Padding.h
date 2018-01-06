#ifndef PADDING_PADDING_H_
#define PADDING_PADDING_H_

#include "common/StaticBuffer.h"

namespace crypto {

class Padding {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    virtual bool pad(StaticByteBufferBase&, const Size) const = 0;

    virtual void unpad(StaticByteBufferBase&) const = 0;
};

class PaddingNone : public Padding {
public:
    virtual bool pad(StaticByteBufferBase& buf, const Size blockSize) const override {
        return buf.size() % blockSize == 0;
    }

    virtual void unpad(StaticByteBufferBase&) const override {}
};

} // namespace crypto

#endif
