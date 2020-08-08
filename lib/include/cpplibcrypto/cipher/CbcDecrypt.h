#ifndef CPPLIBCRYPTO_CIPHER_CBCDECRYPT_H_
#define CPPLIBCRYPTO_CIPHER_CBCDECRYPT_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/StaticBuffer.h"
#include "cpplibcrypto/buffer/utils/bufferUtils.h"
#include "cpplibcrypto/cipher/BlockCipher.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/common/InitializationVector.h"
#include "cpplibcrypto/common/Key.h"
#include "cpplibcrypto/common/common.h"
#include "cpplibcrypto/padding/Padding.h"

NAMESPACE_CRYPTO_BEGIN

/// Block cipher CBC decryptor
class CbcDecrypt {
public:
    /// Constructs decryptor using the provided cipher algorithm, key and IV
    /// \param cipher Block cipher instance
    /// \param key The key for the cipher
    /// \param IV IV for the CB chain. The size has to match the cipher block size
    /// \throws Exception in case the IV size does not match the cipher block size
    CbcDecrypt(const BlockCipher& cipher, InitializationVector& iv)
        : mCipher(cipher)
        , mIv(iv) {
        if (mIv.size() != mCipher.getBlockSize()) {
            throw Exception("CBC-Mode: The Initialization Vector size does not match the cipher block size");
        }
    }

    /// Decrypts the given input
    /// \param in The data to be decrypted
    /// \param out A buffer to which the decrypted data will be pushed. The buffer is expected to have push()
    /// and size() methods.
    template <typename TBuffer>
    Size update(BufferSlice<const Byte> in, TBuffer& out) {
        const Size blockSize = mCipher.getBlockSize();
        StaticBuffer<Byte, 16> buffer;
        ASSERT(mLeftoverBuffer.size() <= blockSize);

        buffer.insert(buffer.end(), mLeftoverBuffer.begin(), mLeftoverBuffer.end());

        // In case this is a full block, we will not decrypt it yet. We want to keep the last block for the
        // final round so we can unpad the it.
        const bool isFullBlock = ((buffer.size() + in.size()) % blockSize) == 0;
        const Size numberOfBlocks = ((buffer.size() + in.size()) / blockSize) - int(isFullBlock);

        // If there is some block we should prcess, we can be sure we will process the leftovers from last
        // round (these leftovers are already in the buffer to decrypt) If there, however, isn't a block to
        // process, we cannot clear it since we would throw away the already gathered, but unprocessed
        // leftovers from previous rounds.
        if (numberOfBlocks > 0) {
            mLeftoverBuffer.clear();
        }

        Size processedInput = 0;
        for (Size block = 0; block < numberOfBlocks; ++block) {
            const Size toProcess = blockSize - buffer.size();
            const Size blockStart = processedInput;
            const Size blockEnd = blockStart + toProcess;

            buffer.insert(buffer.end(), in.begin() + blockStart, in.begin() + blockEnd);
            ASSERT(buffer.size() == blockSize);
            StaticBuffer<Byte, 16> newIv;
            newIv << buffer;
            mCipher.decryptBlock(buffer);
            bufferUtils::pushXored(out, buffer.cbegin(), buffer.cend(), mIv.cbegin());
            processedInput += toProcess;
            mIv.setNew(newIv.begin());
            buffer.clear();
        }
        ASSERT(in.size() - processedInput <= blockSize);
        mLeftoverBuffer.insert(mLeftoverBuffer.end(), in.begin() + processedInput, in.end());

        return out.size(); // return how many bytes were decrypted
    }

    /// Removes padding
    template <typename TBuffer>
    void finalize(TBuffer& out, const Padding& padder) {
        ASSERT(mLeftoverBuffer.size() == mCipher.getBlockSize());
        mCipher.decryptBlock(mLeftoverBuffer);
        bufferUtils::pushXored(out, mLeftoverBuffer.cbegin(), mLeftoverBuffer.cend(), mIv.cbegin());
        padder.unpad(out);
        mLeftoverBuffer.clear();
    }

    /// Resets the CB chain
    void resetChain() { mIv.reset(); }

private:
    // Forbid temporary BlockCipher
    CbcDecrypt(const BlockCipher&& cipher, InitializationVector& iv) = delete;

    const BlockCipher& mCipher;
    InitializationVector& mIv;
    StaticBuffer<Byte, 16> mLeftoverBuffer;
};

NAMESPACE_CRYPTO_END

#endif
