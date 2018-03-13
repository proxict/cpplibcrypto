#ifndef CPPLIBCRYPTO_CIPHER_MODEOFOPERATION_H_
#define CPPLIBCRYPTO_CIPHER_MODEOFOPERATION_H_

#include "cpplibcrypto/buffer/BufferView.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/cipher/BlockCipher.h"
#include "cpplibcrypto/padding/Padding.h"

NAMESPACE_CRYPTO_BEGIN

using ByteBufferView = BufferView<Byte>;

/// Base class for encryption/decryption operation modes
class ModeOfOperation {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    ModeOfOperation(BlockCipher& cipher, const Key& key) { cipher.setKey(key); }

    virtual ~ModeOfOperation() = default;

    virtual Size update(const ByteBufferView& in, DynamicBuffer<Byte>& out) = 0;
    virtual Size update(const ByteBufferView& in, StaticByteBufferBase& out) = 0;

    virtual void finalize(DynamicBuffer<Byte>& out, const Padding& padder) = 0;
    virtual void finalize(StaticByteBufferBase& out, const Padding& padder) = 0;
};

NAMESPACE_CRYPTO_END

#endif
