#ifndef CIPHER_MODEOFOPERATION_H_
#define CIPHER_MODEOFOPERATION_H_

#include <memory>

#include "cipher/BlockCipher.h"
#include "common/ByteBuffer.h"

namespace crypto {

class ModeOfOperation {
public:
    ModeOfOperation(BlockCipher& cipher, Key&& key) : m_blockCipher(cipher) {
        m_blockCipher.setKey(std::move(key));
    }

    virtual ByteBuffer update(const ByteBuffer&) = 0;

protected:
    BlockCipher& m_blockCipher;
};

} // namespace crypto

#endif
