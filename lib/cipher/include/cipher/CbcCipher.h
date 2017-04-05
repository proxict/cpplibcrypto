#ifndef CIPHER_CBCCIPHER_H_
#define CIPHER_CBCCIPHER_H_

#include "common/ByteBuffer.h"
#include "cipher/BlockCipher.h"

namespace crypto {

template <typename PaddingT>
class CbcCipher {
public:
    CbcCipher(BlockCipher& cipher, ByteBuffer&& key, ByteBuffer&& IV) :
        m_blockCipher(cipher), m_IV(std::move(IV)) {
        m_blockCipher.setKey(std::move(key));
    }

    ByteBuffer encrypt(const ByteBuffer& in) {
        return m_blockCipher.encryptBlock(in);
    }

    ByteBuffer decrypt(const ByteBuffer& in) {
        return m_blockCipher.decryptBlock(in);
    }

    // Note(ProXicT): Needs data length in multiple of BlockSize (because of padding)?
    ByteBuffer update(const ByteBuffer& in) {
        return m_blockCipher.decryptBlock(in);
    }

    ByteBuffer finish() {
        return ByteBuffer{};
    }

private:
    BlockCipher& m_blockCipher;
    ByteBuffer m_IV;
    PaddingT m_padding;
};

} // namespace crypto

#endif

