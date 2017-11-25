#ifndef CIPHER_CBCDECRYPT_H_
#define CIPHER_CBCDECRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/ByteBuffer.h"
#include "common/common.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"

namespace crypto {


class CbcDecrypt : public ModeOfOperation {
public:
    CbcDecrypt(BlockCipher& cipher, const Key& key, InitializationVector& IV)
        : ModeOfOperation(cipher, key), m_IV(IV) {
        if (IV.size() != cipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    std::size_t update(const ByteBufferView& in, StaticByteBufferBase& out) override {
        ASSERT(out.capacity() >= in.size());
        const std::size_t numberOfBlocks = in.size() / m_blockCipher.getBlockSize() - 1;

        for (std::size_t block = 0; block < numberOfBlocks; ++block) {
            ByteBuffer buffer;
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                buffer += in[block * m_blockCipher.getBlockSize() + i];
            }
            m_blockCipher.decryptBlock(buffer);
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                out.push(buffer[i] ^ m_IV[i]);
            }

            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                m_IV[i] = in[block * m_blockCipher.getBlockSize() + i];
            }
        }
        return out.size();
    }
    
    void doFinal(const ByteBufferView& in, StaticByteBufferBase& out) override {
        ASSERT(in.size() == m_blockCipher.getBlockSize());

        ByteBuffer buffer;
        for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
            buffer += in[i];
        }
        m_blockCipher.decryptBlock(buffer);
        for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
            out.push(buffer[i] ^ m_IV[i]);
        }
        
        const byte padding = out.back();
        for (byte i = 0; i < padding; ++i) {
            out.pop();
        }
    }

    void resetChain() {
        m_IV.reset();
    }

private:
    InitializationVector& m_IV;
};

} // namespace crypto

#endif
