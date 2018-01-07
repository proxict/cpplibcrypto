#ifndef PADDING_PADDING_H_
#define PADDING_PADDING_H_

#include "common/DynamicBuffer.h"
#include "common/StaticBuffer.h"

namespace crypto {

class Padding {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    virtual bool pad(DynamicBuffer<Byte>&, const Size) const = 0;
    virtual bool pad(StaticByteBufferBase&, const Size) const = 0;

    virtual void unpad(DynamicBuffer<Byte>&) const = 0;
    virtual void unpad(StaticByteBufferBase&) const = 0;
};

class PaddingNone : public Padding {
public:

    bool pad(DynamicBuffer<Byte>& buf, const Size blockSize) const override {
        return pad<DynamicBuffer<Byte>>(buf, blockSize);
    }
    
    bool pad(StaticByteBufferBase& buf, const Size blockSize) const override {
        return pad<StaticBufferBase<Byte>>(buf, blockSize);
    }

    template <typename TContainer>
    bool pad(TContainer& buf, const Size blockSize) const {
        return buf.size() % blockSize == 0;
    }

    void unpad(DynamicBuffer<Byte>& buf) const override {
        unpad<DynamicBuffer<Byte>>(buf);
    }
    
    void unpad(StaticByteBufferBase& buf) const override {
        unpad<StaticBufferBase<Byte>>(buf);
    }

    template <typename TContainer>
    void unpad(TContainer&) const {}
};

} // namespace crypto

#endif
