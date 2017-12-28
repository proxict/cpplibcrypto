#ifndef CIPHER_BLOCKCIPHER_H_
#define CIPHER_BLOCKCIPHER_H_

#include "cipher/SymmetricAlgorithm.h"

#include "common/StaticBuffer.h"
#include "common/Key.h"

namespace crypto {

class BlockCipher : public SymmetricAlgorithm {
    using StaticByteBufferBase = StaticBufferBase<Byte>;
public:
    BlockCipher() = default;

    virtual Size getBlockSize() const = 0;

    virtual void encryptBlock(StaticByteBufferBase&) = 0;

    virtual void decryptBlock(StaticByteBufferBase&) = 0;
};

} // namespace crypto

#endif

