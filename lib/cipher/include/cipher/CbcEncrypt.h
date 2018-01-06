#ifndef CIPHER_CBCENCRYPT_H_
#define CIPHER_CBCENCRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"
#include "common/common.h"

namespace crypto {

class CbcEncrypt : public ModeOfOperation {
public:
    CbcEncrypt(BlockCipher& cipher, const Key& key, InitializationVector& iv) : ModeOfOperation(cipher, key), mCipher(cipher), mIv(iv) {
        if (mIv.size() != mCipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    Size update(const ByteBufferView& in, StaticByteBufferBase& out) override {
        const Size blockSize = mCipher.getBlockSize();
        ASSERT(out.capacity() >= in.size());
        ASSERT(out.capacity() >= blockSize);
        if (in.size() < blockSize && in.size() % blockSize != 0) {
            return 0;
        }

        const Size numberOfBlocks = in.size() / blockSize;
        for (Size block = 0; block < numberOfBlocks; ++block) {
            StaticBuffer<Byte, 16> buffer;
            for (Byte i = 0; i < blockSize; ++i) {
                buffer.push(in[block * blockSize + i] ^ mIv[i]);
            }
            mCipher.encryptBlock(buffer);

            out.insert(out.end(), buffer.begin(), buffer.end());

            for (Byte i = 0; i < blockSize; ++i) {
                mIv[i] = buffer[i];
            }
        }
        return out.size(); // return how many bytes were encrypted
    }

    void doFinal(const ByteBufferView& in, StaticByteBufferBase& out, const Padding& padder) override {
        ASSERT(in.size() < mCipher.getBlockSize());
        StaticBuffer<Byte, 16> buffer;
        buffer.insert(buffer.end(), in.begin(), in.end());
        if (!padder.pad(buffer, mCipher.getBlockSize())) {
            throw Exception("Buffer size must be a multiple of block size for encryption");
        }
        if (buffer.size() == 0) {
            return;
        }

        for (Byte i = 0; i < buffer.size(); ++i) {
            buffer[i] ^= mIv[i];
        }

        mCipher.encryptBlock(buffer);
        out.insert(out.end(), buffer.begin(), buffer.end());
    }

    void resetChain() { mIv.reset(); }

private:
    BlockCipher& mCipher;
    InitializationVector& mIv;
};

} // namespace crypto

#endif
