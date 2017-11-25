#ifndef CIPHER_MODEOFOPERATION_H_
#define CIPHER_MODEOFOPERATION_H_

#include "cipher/BlockCipher.h"
#include "common/StaticByteBuffer.h"
#include "common/BufferView.h"

namespace crypto {

using ByteBufferView = BufferView<byte>;

class ModeOfOperation {
public:
    ModeOfOperation(BlockCipher& cipher, const Key& key) : m_blockCipher(cipher) {
        m_blockCipher.setKey(key);
    }

    virtual std::size_t update(const ByteBufferView& in, StaticByteBufferBase& out) = 0;

    virtual void doFinal(const ByteBufferView& in, StaticByteBufferBase& out) = 0;

protected:
    BlockCipher& m_blockCipher;
};

} // namespace crypto

#endif
