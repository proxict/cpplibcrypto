#ifndef CIPHER_MODEOFOPERATION_H_
#define CIPHER_MODEOFOPERATION_H_

#include "cipher/BlockCipher.h"
#include "common/BufferView.h"
#include "common/StaticBuffer.h"
#include "padding/Padding.h"

NAMESPACE_CRYPTO_BEGIN

using ByteBufferView = BufferView<Byte>;

/// Base class for encryption/decryption operation modes
class ModeOfOperation {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    ModeOfOperation(BlockCipher& cipher, const Key& key) { cipher.setKey(key); }

    virtual Size update(const ByteBufferView& in, DynamicBuffer<Byte>& out) = 0;
    virtual Size update(const ByteBufferView& in, StaticByteBufferBase& out) = 0;

    virtual void doFinal(DynamicBuffer<Byte>& out, const Padding& padder) = 0;
    virtual void doFinal(StaticByteBufferBase& out, const Padding& padder) = 0;
};

NAMESPACE_CRYPTO_END

#endif
