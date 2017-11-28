#ifndef CIPHER_CBCDECRYPT_H_
#define CIPHER_CBCDECRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/ByteBuffer.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"
#include "common/common.h"

namespace crypto {

class CbcDecrypt : public ModeOfOperation {
public:
    CbcDecrypt(BlockCipher& cipher, const Key& key, InitializationVector& IV) : ModeOfOperation(cipher, key), m_IV(IV) {
        if (IV.size() != cipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    std::size_t update(const ByteBufferView& in, StaticByteBufferBase& out) override {
        ASSERT(in.size() % m_blockCipher.getBlockSize() == 0);
        ASSERT(out.capacity() >= in.size());
        const std::size_t numberOfBlocks = in.size() / m_blockCipher.getBlockSize() - 1;

        for (std::size_t block = 0; block < numberOfBlocks; ++block) {
            StaticByteBuffer<16> buffer;
            for (byte i = 0; i < m_blockCipher.getBlockSize(); ++i) {
                buffer.push(in[block * m_blockCipher.getBlockSize() + i]);
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

    void doFinal(const ByteBufferView& in, StaticByteBufferBase& out, const Padding& padder) override {
        ASSERT(in.size() == m_blockCipher.getBlockSize());
        StaticByteBuffer<16> buffer;
        for (const byte b : in) {
            buffer.push(b);
        }
        m_blockCipher.decryptBlock(buffer);
        for (byte i = 0; i < buffer.size(); ++i) {
            out.push(buffer[i] ^ m_IV[i]);
        }
        padder.unpad(out);
    }

    void resetChain() { m_IV.reset(); }

private:
    InitializationVector& m_IV;
};

} // namespace crypto

#endif
