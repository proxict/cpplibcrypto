#ifndef CIPHER_SHA1_H_
#define CIPHER_SHA1_H_

#include <iostream>
#include "common/BufferView.h"
#include "common/DynamicBuffer.h"
#include "common/StaticBuffer.h"

NAMESPACE_CRYPTO_BEGIN

class Sha1Core {
public:
    using Word = uint32_t;
    static Word rotateLeft(const Word value, const Byte bits) { return (value << bits) | (value >> (32 - bits)); }

    static Word f(const Byte t, const Word B, const Word C, const Word D) {
        if (t <= 19) {
            return (B & C) | ((~B) & D);
        } else if (t <= 39) {
            return B ^ C ^ D;
        } else if (t <= 59) {
            return (B & C) | (B & D) | (C & D);
        } else if (t <= 79) {
            return B ^ C ^ D;
        }
        ASSERT(false);
    }

    static Word k(const Byte t) {
        if (t <= 19) {
            return 0x5A827999;
        } else if (t <= 39) {
            return 0x6ED9EBA1;
        } else if (t <= 59) {
            return 0x8F1BBCDC;
        } else if (t <= 79) {
            return 0xCA62C1D6;
        }
        ASSERT(false);
    }
};

class Sha1 {
public:
    static constexpr int DIGEST_SIZE = 20;
    using Word = Sha1Core::Word;

    Sha1() { reset(); }

    template <typename TBuffer>
    void update(const TBuffer& in) {
        static constexpr Size blockSize = 64;
        StaticBuffer<Byte, 64> buffer;
        ASSERT(mLeftoverBuffer.size() < blockSize);

        buffer.insert(buffer.end(), mLeftoverBuffer.cbegin(), mLeftoverBuffer.cend());

        Size processedInput = 0;
        const Size numberOfBlocks = (buffer.size() + in.size()) / blockSize;
        if (numberOfBlocks > 0) {
            mLeftoverBuffer.clear();
        }
        for (Size block = 0; block < numberOfBlocks; ++block) {
            const Size toProcess = blockSize - buffer.size();
            const Size blockStart = processedInput;
            const Size blockEnd = blockStart + toProcess;

            buffer.insert(buffer.end(), in.cbegin() + blockStart, in.cbegin() + blockEnd);

            ASSERT(buffer.size() == blockSize);
            processBlock(buffer);
            processedInput += toProcess;
            buffer.clear();
        }

        ASSERT(in.size() - processedInput < blockSize);
        mLeftoverBuffer.insert(mLeftoverBuffer.end(), in.begin() + processedInput, in.end());
    }

    ByteBuffer finalize() {
        processBlock(mLeftoverBuffer);
        ByteBuffer digest;
        for (int i = 0; i < DIGEST_SIZE; ++i) {
            digest.push(mH[i >> 2] >> 8 * (3 - (i & 0x03)));
        }
        mLeftoverBuffer.clear();
        return digest;
    }

    void reset() {
        mH.clear();
        mH.push(0x67452301);
        mH.push(0xEFCDAB89);
        mH.push(0x98BADCFE);
        mH.push(0x10325476);
        mH.push(0xC3D2E1F0);
    }

private:
    using ByteBufferView = BufferView<Byte>;

    void padMessage(ByteBufferView message) { (void)message; }

    void processBlock(const ByteBufferView& block) {
        for (const auto& it : block) {
            std::cout << char(it);
        }
        const StaticBuffer<Word, 4> k({0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6});
        StaticBuffer<Word, 80> W(80);
        Word A, B, C, D, E;
        Word temp;
    }

    StaticBuffer<Word, 5> mH;
    StaticBuffer<Byte, 64> mLeftoverBuffer;
};

NAMESPACE_CRYPTO_END

#endif
