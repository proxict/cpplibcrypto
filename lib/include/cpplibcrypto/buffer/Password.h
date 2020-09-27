#ifndef CPPLIBCRYPTO_BUFFER_PASSWORD_H_
#define CPPLIBCRYPTO_BUFFER_PASSWORD_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"

namespace crypto {

class Password {
public:
    using Iterator = DynamicBuffer<Byte>::Iterator;
    using ConstIterator = DynamicBuffer<Byte>::ConstIterator;
    using iterator = DynamicBuffer<Byte>::iterator;
    using const_iterator = DynamicBuffer<Byte>::const_iterator;

    Password() = default;

    template <typename TBuffer>
    Password(const TBuffer& buffer) {
        mData.insert(mData.end(), buffer.begin(), buffer.end());
    }

    Password& operator=(const Password& other) {
        mData.clear();
        mData.insert(mData.end(), other.begin(), other.end());
        return *this;
    }

    Password(const Password& other) { *this = other; }

    Password(Password&& other) { *this = std::move(other); }

    Password& operator=(Password&& other) {
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
    DynamicBuffer<Byte> mData;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_BUFFER_PASSWORD_H_
