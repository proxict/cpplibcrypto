#ifndef CIPHER_CBCENCRYPT_H_
#define CIPHER_CBCENCRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/ByteBuffer.h"
#include "common/common.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"

namespace crypto {

class CbcEncrypt : public ModeOfOperation {
public:
    CbcEncrypt(BlockCipher& cipher, const Key& key, InitializationVector& IV)
        : ModeOfOperation(cipher, key), m_IV(IV) {
        if (IV.size() != cipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    std::size_t update(const ByteBufferView& in, StaticByteBufferBase& out) override {
        ASSERT(out.capacity() >= in.size());
        ASSERT(out.capacity() >= m_blockCipher.getBlockSize());
        const std::size_t numberOfBlocks = in.size() / m_blockCipher.getBlockSize();

        for (std::size_t block = 0; block < numberOfBlocks; ++block) {
            ByteBuffer buffer;
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                buffer += in[block * m_blockCipher.getBlockSize() + i] ^ m_IV[i];
            }
            m_blockCipher.encryptBlock(buffer);

            out.insert(&buffer[0], &buffer[0] + buffer.size());

            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                m_IV[i] = buffer[i];
            }
        }
        return out.size(); // return how many bytes were encrypted
    }

    void doFinal(const ByteBufferView& in, StaticByteBufferBase& out) override {
        ASSERT(in.size() < m_blockCipher.getBlockSize());
        ByteBuffer buffer;
        for (byte i = 0; i < in.size(); ++i) {
            buffer += in[i] ^ m_IV[i];
        }

        // Put this in separate class which will take care of padding - IV?
        const byte padding = m_blockCipher.getBlockSize() - in.size();
        for (std::size_t i = 0; i < padding; ++i) {
            buffer += padding ^ m_IV[in.size() + i];
        }
        // end
        
        ASSERT(buffer.size() == m_blockCipher.getBlockSize());
        m_blockCipher.encryptBlock(buffer);

        out.insert(&buffer[0], &buffer[0] + buffer.size());
    }

    void resetChain() {
        m_IV.reset();
    }

private:
    InitializationVector& m_IV;
};

} // namespace crypto

#endif
