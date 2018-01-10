#ifndef CIPHER_CBCENCRYPT_H_
#define CIPHER_CBCENCRYPT_H_

#include "cipher/ModeOfOperation.h"

#include "common/DynamicBuffer.h"
#include "common/Exception.h"
#include "common/InitializationVector.h"
#include "common/Key.h"
#include "common/common.h"
#include "common/bufferUtils.h"

namespace crypto {

class CbcEncrypt : public ModeOfOperation {
public:
    CbcEncrypt(BlockCipher& cipher, const Key& key, InitializationVector& iv) : ModeOfOperation(cipher, key), mCipher(cipher), mIv(iv) {
        if (mIv.size() != mCipher.getBlockSize()) {
            throw Exception("The Initialization Vector size does not match the cipher block size");
        }
    }

    Size update(const ByteBufferView& in, DynamicBuffer<Byte>& out) override {
        return update<DynamicBuffer<Byte>>(in, out);
    }

    Size update(const ByteBufferView& in, StaticBufferBase<Byte>& out) override {
        return update<StaticBufferBase<Byte>>(in, out);
    }

    template <typename TContainer>
    Size update(const ByteBufferView& in, TContainer& out) {
        const Size blockSize = mCipher.getBlockSize();
        if (in.size() < blockSize && in.size() % blockSize != 0) {
            return 0;
        }

        const Size numberOfBlocks = in.size() / blockSize;
        for (Size block = 0; block < numberOfBlocks; ++block) {
            StaticBuffer<Byte, 16> buffer;
            const Size currentBlockStart = block * blockSize;
            const Size currentBlockEnd = currentBlockStart + blockSize;
            bufferUtils::pushXored(buffer, in.begin() + currentBlockStart, in.begin() + currentBlockEnd, mIv.begin());

            mCipher.encryptBlock(buffer);

            out.insert(out.end(), buffer.begin(), buffer.end());
            mIv.setNew(buffer.begin());
        }
        return out.size(); // return how many bytes were encrypted
    }

    void doFinal(const ByteBufferView& in, DynamicBuffer<Byte>& out, const Padding& padder) override {
        doFinal<DynamicBuffer<Byte>>(in, out, padder);
    }

    void doFinal(const ByteBufferView& in, StaticBufferBase<Byte>& out, const Padding& padder) override {
        doFinal<StaticBufferBase<Byte>>(in, out, padder);
    }

    template <typename TContainer>
    void doFinal(const ByteBufferView& in, TContainer& out, const Padding& padder) {
        ASSERT(in.size() < mCipher.getBlockSize());
        StaticBuffer<Byte, 16> buffer;
        buffer.insert(buffer.end(), in.begin(), in.end());
        if (!padder.pad(buffer, mCipher.getBlockSize())) {
            throw Exception("Buffer size must be a multiple of block size for encryption");
        }
        if (buffer.size() == 0) {
            return;
        }

        bufferUtils::xorBuffer(buffer, mIv);

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
