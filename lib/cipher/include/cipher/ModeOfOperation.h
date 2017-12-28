#ifndef CIPHER_MODEOFOPERATION_H_
#define CIPHER_MODEOFOPERATION_H_

#include "cipher/BlockCipher.h"
#include "common/StaticBuffer.h"
#include "common/BufferView.h"
#include "padding/Padding.h"

namespace crypto {

using ByteBufferView = BufferView<Byte>;

class ModeOfOperation {
public:
    using StaticByteBufferBase = StaticBufferBase<Byte>;

    ModeOfOperation(BlockCipher& cipher, const Key& key) : m_blockCipher(cipher) {
        m_blockCipher.setKey(key);
    }

    virtual Size update(const ByteBufferView& in, StaticByteBufferBase& out) = 0;

    virtual void doFinal(const ByteBufferView& in, StaticByteBufferBase& out, const Padding& padder) = 0;

protected:
    BlockCipher& m_blockCipher;
};

} // namespace crypto

#endif
