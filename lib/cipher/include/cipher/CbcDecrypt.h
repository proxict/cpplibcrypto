#ifndef CIPHER_CBCDECRYPT_H_
#define CIPHER_CBCDECRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"
#include "common/common.h"

namespace crypto {

class CbcDecrypt : public ModeOfOperation {
public:
    CbcDecrypt(BlockCipher& cipher, const Key& key, InitializationVector& iv) : ModeOfOperation(cipher, key), mCipher(cipher), mIv(iv) {
        if (mIv.size() != mCipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    Size update(const ByteBufferView& in, StaticByteBufferBase& out) override {
        const Size blockSize = mCipher.getBlockSize();
        ASSERT(in.size() % blockSize == 0);
        ASSERT(out.capacity() >= in.size());
        const Size numberOfBlocks = in.size() / blockSize - 1;

        for (Size block = 0; block < numberOfBlocks; ++block) {
            StaticBuffer<Byte, 16> buffer;
            const Size currentBlockStart = block * blockSize;
            const Size currentBlockEnd = currentBlockStart + blockSize;
            buffer.insert(buffer.end(), in.begin() + currentBlockStart, in.begin() + currentBlockEnd);

            ByteBufferView view(buffer);
            mCipher.decryptBlock(view);
            for (Byte i = 0; i < blockSize; ++i) {
                out.push(buffer[i] ^ mIv[i]);
            }

            for (Byte i = 0; i < blockSize; ++i) {
                mIv[i] = in[block * blockSize + i];
            }
        }
        return out.size();
    }

    void doFinal(const ByteBufferView& in, StaticByteBufferBase& out, const Padding& padder) override {
        ASSERT(in.size() == mCipher.getBlockSize());
        StaticBuffer<Byte, 16> buffer;
        buffer.insert(buffer.end(), in.begin(), in.end());

        ByteBufferView view(buffer);
        mCipher.decryptBlock(view);
        for (Byte i = 0; i < buffer.size(); ++i) {
            out.push(buffer[i] ^ mIv[i]);
        }
        padder.unpad(out);
    }

    void resetChain() { mIv.reset(); }

private:
    BlockCipher& mCipher;
    InitializationVector& mIv;
};

} // namespace crypto

#endif
