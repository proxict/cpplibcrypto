#ifndef CIPHER_BLOCKCIPHERSIZED_H_
#define CIPHER_BLOCKCIPHERSIZED_H_

#include "cipher/BlockCipher.h"

#include <cstddef> // std::size_t

namespace crypto {

template<std::size_t blockSize>
class BlockCipherSized : public BlockCipher {
public:
    std::size_t getBlockSize() const override { return blockSize; }

protected:
    BlockCipherSized() = default;
};

} // namespace crypto

#endif

