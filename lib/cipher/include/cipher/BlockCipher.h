#ifndef CIPHER_BLOCKCIPHER_H_
#define CIPHER_BLOCKCIPHER_H_

#include "cipher/SymmetricAlgorithm.h"

#include "common/BufferView.h"
#include "common/Key.h"

namespace crypto {

class BlockCipher : public SymmetricAlgorithm {
public:
    using ByteBufferView = BufferView<Byte>;

    BlockCipher() = default;

    virtual Size getBlockSize() const = 0;

    virtual void encryptBlock(ByteBufferView&) = 0;

    virtual void decryptBlock(ByteBufferView&) = 0;
};

} // namespace crypto

#endif

