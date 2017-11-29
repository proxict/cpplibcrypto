#ifndef CIPHER_BLOCKCIPHERSIZED_H_
#define CIPHER_BLOCKCIPHERSIZED_H_

#include "cipher/BlockCipher.h"

namespace crypto {

template<Size TBlockSize>
class BlockCipherSized : public BlockCipher {
public:
    Size getBlockSize() const override { return TBlockSize; }

protected:
    BlockCipherSized() = default;
};

} // namespace crypto

#endif

