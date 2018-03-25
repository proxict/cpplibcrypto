#ifndef CPPLIBCRYPTO_BUFFER_SALT_H_
#define CPPLIBCRYPTO_BUFFER_SALT_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"

NAMESPACE_CRYPTO_BEGIN

class Salt {
public:
    using Iterator = DynamicBuffer<Byte>::Iterator;
    using ConstIterator = DynamicBuffer<Byte>::ConstIterator;
    using iterator = DynamicBuffer<Byte>::iterator;
    using const_iterator = DynamicBuffer<Byte>::const_iterator;

    Salt() = default;

    template <typename TBuffer>
    Salt(const TBuffer& buffer) {
        mData.insert(mData.end(), buffer.begin(), buffer.end());
    }

    Salt(Salt&& other) { *this = std::move(other); }

    Salt& operator=(Salt&& other) {
        std::swap(mData, other.mData);
        return *this;
    }

    template <typename TBuffer>
    void set(const TBuffer& buffer) {
        mData.clear();
        mData.insert(mData.end(), buffer.begin(), buffer.end());
    }

    Size size() const { return mData.size(); }

    Iterator begin() { return mData.begin(); }

    Iterator end() { return mData.end(); }

    ConstIterator begin() const { return mData.begin(); }

    ConstIterator end() const { return mData.end(); }

    ConstIterator cbegin() const { return mData.begin(); }

    ConstIterator cend() const { return mData.end(); }

private:
    Salt& operator=(const Salt&) = delete;
    Salt(const Salt&) = delete;
    DynamicBuffer<Byte> mData;
};

NAMESPACE_CRYPTO_END

#endif
