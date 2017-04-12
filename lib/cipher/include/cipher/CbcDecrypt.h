#ifndef CIPHER_CBCDECRYPT_H_
#define CIPHER_CBCDECRYPT_H_

#include "cipher/ModeOfOperation.h"

#include <memory>

#include "common/ByteBuffer.h"
#include "common/Exception.h"
#include "common/Key.h"

namespace crypto {

class CbcDecrypt : public ModeOfOperation {
public:
    CbcDecrypt(BlockCipher& cipher, Key&& key, ByteBuffer&& IV)
        : ModeOfOperation(cipher, std::move(key)), m_IV(std::move(IV)) {}

    ByteBuffer update(const ByteBuffer& in) override {
        assert(in.size() % m_blockCipher.getBlockSize() == 0);
        const std::size_t numberOfBlocks = in.size() / m_blockCipher.getBlockSize();

        ByteBuffer out;
        for (std::size_t block = 0; block < numberOfBlocks; ++block) {
            ByteBuffer buffer;
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                buffer += in[block * m_blockCipher.getBlockSize() + i];
            }
            m_blockCipher.decryptBlock(buffer);
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                out += buffer[i] ^ m_IV[i];
            }

            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                m_IV[i] = in[block * m_blockCipher.getBlockSize() + i];
            }
        }
        return out;
    }

private:
    ByteBuffer m_IV;
};

} // namespace crypto

#endif

