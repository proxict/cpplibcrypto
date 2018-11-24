#ifndef CPPLIBCRYPTO_CIPHER_CBCENCRYPT_H_
#define CPPLIBCRYPTO_CIPHER_CBCENCRYPT_H_

#include "cpplibcrypto/cipher/ModeOfOperation.h"

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/InitializationVector.h"
#include "cpplibcrypto/common/Key.h"
#include "cpplibcrypto/common/common.h"

NAMESPACE_CRYPTO_BEGIN

/// Block cipher CBC encryptor
class CbcEncrypt : public ModeOfOperation {
public:
    /// Constructs encryptor using the provided cipher algorithm, key and IV
    /// \param cipher Block cipher instance
    /// \param key The key for the cipher
    /// \param IV IV for the CB chain. The size has to match the cipher block size
    /// \throws Exception in case the IV size does not match the cipher block size
    CbcEncrypt(BlockCipher& cipher, const Key& key, InitializationVector& iv)
        : ModeOfOperation(cipher, key)
        , mCipher(cipher)
        , mIv(iv) {
        if (mIv.size() != mCipher.getBlockSize()) {
            throw Exception("CBC-Mode: The Initialization Vector size does not match the cipher block size");
        }
    }

    Size update(ConstByteBufferView in, DynamicBuffer<Byte>& out) override {
        return update<DynamicBuffer<Byte>>(in, out);
    }

    Size update(ConstByteBufferView in, StaticBufferBase<Byte>& out) override {
        return update<StaticBufferBase<Byte>>(in, out);
    }

    /// Encrypts the given input
    /// \param in The data to be encrypted
    /// \param out A buffer to which the encrypted data will be pushed. The buffer is expected to have push()
    /// and size() methods.
    template <typename TBuffer>
    Size update(ConstByteBufferView in, TBuffer& out) {
        const Size blockSize = mCipher.getBlockSize();
        StaticBuffer<Byte, 16> buffer;
        ASSERT(mLeftoverBuffer.size() < blockSize);

        bufferUtils::pushXored(buffer, mLeftoverBuffer.cbegin(), mLeftoverBuffer.cend(), mIv.cbegin());

        Size processedInput = 0;
        const Size numberOfBlocks = (buffer.size() + in.size()) / blockSize;
        if (numberOfBlocks > 0) {
            mLeftoverBuffer.clear();
        }
        for (Size block = 0; block < numberOfBlocks; ++block) {
            const Size toProcess = blockSize - buffer.size();
            const Size blockStart = processedInput;
            const Size blockEnd = blockStart + toProcess;

            bufferUtils::pushXored(
                buffer, in.cbegin() + blockStart, in.cbegin() + blockEnd, mIv.cbegin() + buffer.size());

            ASSERT(buffer.size() == blockSize);
            mCipher.encryptBlock(buffer);
            processedInput += toProcess;

            out.insert(out.end(), buffer.begin(), buffer.end());
            mIv.setNew(buffer.begin());
            buffer.clear();
        }

        ASSERT(in.size() - processedInput < blockSize);
        mLeftoverBuffer.insert(mLeftoverBuffer.end(), in.begin() + processedInput, in.end());

        return out.size(); // return how many bytes were encrypted
    }

    void finalize(DynamicBuffer<Byte>& out, const Padding& padder) override {
        finalize<DynamicBuffer<Byte>>(out, padder);
    }

    void finalize(StaticBufferBase<Byte>& out, const Padding& padder) override {
        finalize<StaticBufferBase<Byte>>(out, padder);
    }

    /// Applies padding using the provided scheme
    /// \throws Exception if the provided padding algorithm fails
    template <typename TBuffer>
    void finalize(TBuffer& out, const Padding& padder) {
        ASSERT(mLeftoverBuffer.size() < mCipher.getBlockSize());
        if (!padder.pad(mLeftoverBuffer, mCipher.getBlockSize())) {
            throw Exception("CBC-Mode: Buffer size must be a multiple of block size for encryption");
        }
        // This is valid in case no padding is applied
        if (mLeftoverBuffer.size() == 0) {
            return;
        }

        ASSERT(mLeftoverBuffer.size() == mCipher.getBlockSize());
        bufferUtils::xorBuffer(mLeftoverBuffer, mIv);
        mCipher.encryptBlock(mLeftoverBuffer);
        out.insert(out.end(), mLeftoverBuffer.begin(), mLeftoverBuffer.end());
        mLeftoverBuffer.clear();
    }

    /// Resets the CB chain
    void resetChain() { mIv.reset(); }

private:
    StaticBuffer<Byte, 16> mLeftoverBuffer;
    BlockCipher& mCipher;
    InitializationVector& mIv;
};

NAMESPACE_CRYPTO_END

#endif
