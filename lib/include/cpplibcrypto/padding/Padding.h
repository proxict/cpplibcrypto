#ifndef CPPLIBCRYPTO_PADDING_PADDING_H_
#define CPPLIBCRYPTO_PADDING_PADDING_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"

namespace crypto {

/// Base class for padding implementations
class Padding {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    virtual ~Padding() = default;

    virtual bool pad(DynamicBuffer<Byte>&, const Size) const = 0;
    virtual bool pad(StaticByteBufferBase&, const Size) const = 0;

    virtual void unpad(DynamicBuffer<Byte>&) const = 0;
    virtual void unpad(StaticByteBufferBase&) const = 0;
};

/// Helper class implementing no padding. Useful in situations where a i.e. block cipher operations are
/// performed on an already block-size aligned data.
class PaddingNone : public Padding {
public:
    bool pad(DynamicBuffer<Byte>& buf, const Size blockSize) const override {
        return pad<DynamicBuffer<Byte>>(buf, blockSize);
    }

    bool pad(StaticByteBufferBase& buf, const Size blockSize) const override {
        return pad<StaticBufferBase<Byte>>(buf, blockSize);
    }

    /// Returns whether or not the buffer size is a multiple of the given block size
    template <typename TBuffer>
    bool pad(TBuffer& buf, const Size blockSize) const {
        return buf.size() % blockSize == 0;
    }

    void unpad(DynamicBuffer<Byte>& buf) const override { unpad<DynamicBuffer<Byte>>(buf); }

    void unpad(StaticByteBufferBase& buf) const override { unpad<StaticBufferBase<Byte>>(buf); }

    /// In this implementation this function is no-op
    template <typename TBuffer>
    void unpad(TBuffer&) const {}
};

} // namespace crypto

#endif // CPPLIBCRYPTO_PADDING_PADDING_H_
