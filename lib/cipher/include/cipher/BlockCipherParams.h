#ifndef CIPHER_BLOCKCIPHERPARAMS_H_
#define CIPHER_BLOCKCIPHERPARAMS_H_

#include "cipher/BlockCipher.h"
#include "cipher/KeySize.h"

namespace crypto {

template<std::size_t blockSize, std::size_t minKeySize, std::size_t maxKeySize = 0, std::size_t mod = 1>
class BlockCipherParams : public BlockCipher {
public:
    std::size_t getBlockSize() const override { return blockSize; }

    KeySize getKeySize() const override {
        return KeySize(minKeySize, maxKeySize, mod);
    }
};

} // namespace crypto

#endif

