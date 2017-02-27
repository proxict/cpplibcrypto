#ifndef COMMON_BYTE_BUFFER_H_
#define COMMON_BYTE_BUFFER_H_

#include <string>
#include <utility>
#include <vector>

#include "common/common.h"

namespace crypto {

class ByteBuffer : private std::vector<byte> {
public:
    using std::vector<byte>::vector;
    using std::vector<byte>::assign;
    using std::vector<byte>::at;
    using std::vector<byte>::back;
    using std::vector<byte>::begin;
    using std::vector<byte>::capacity;
    using std::vector<byte>::cbegin;
    using std::vector<byte>::cend;
    using std::vector<byte>::clear;
    using std::vector<byte>::const_iterator;
    using std::vector<byte>::const_pointer;
    using std::vector<byte>::const_reference;
    using std::vector<byte>::const_reverse_iterator;
    using std::vector<byte>::crbegin;
    using std::vector<byte>::crend;
    using std::vector<byte>::data;
    using std::vector<byte>::difference_type;
    using std::vector<byte>::emplace;
    using std::vector<byte>::emplace_back;
    using std::vector<byte>::empty;
    using std::vector<byte>::end;
    using std::vector<byte>::erase;
    using std::vector<byte>::front;
    using std::vector<byte>::get_allocator;
    using std::vector<byte>::insert;
    using std::vector<byte>::iterator;
    using std::vector<byte>::max_size;
    using std::vector<byte>::operator=;
    using std::vector<byte>::operator[];
    using std::vector<byte>::pointer;
    using std::vector<byte>::pop_back;
    using std::vector<byte>::push_back;
    using std::vector<byte>::rbegin;
    using std::vector<byte>::reference;
    using std::vector<byte>::rend;
    using std::vector<byte>::reserve;
    using std::vector<byte>::resize;
    using std::vector<byte>::reverse_iterator;
    using std::vector<byte>::shrink_to_fit;
    using std::vector<byte>::size;
    using std::vector<byte>::size_type;
    using std::vector<byte>::swap;
    using std::vector<byte>::value_type;

    ByteBuffer() = default;

    ByteBuffer(ByteBuffer&& other) noexcept {
        *this = std::move(other);
    }

    ByteBuffer& operator = (ByteBuffer&& other) noexcept {
        std::vector<byte>::operator =(other);
        return *this;
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        this->insert(this->end(), b.begin(), b.end());
        return *this;
    }

    ByteBuffer& operator+=(const byte b) {
        this->push_back(b);
        return *this;
    }

    ByteBuffer& operator+(const byte rhs) {
        push_back(rhs);
        return *this;
    }

    ByteBuffer& operator+(const ByteBuffer& rhs) {
        insert(end(), rhs.begin(), rhs.end());
        return *this;
    }

    friend ByteBuffer& operator+(const byte lhs, ByteBuffer& rhs) {
        rhs.insert(rhs.begin(), lhs);
        return rhs;
    }

    bool operator==(const ByteBuffer& rhs) const {
        return size() == rhs.size() && std::equal(begin(), end(), rhs.begin());
    }

    virtual ~ByteBuffer() = default;

private:
    ByteBuffer(const std::vector<byte>&) = delete;
    ByteBuffer& operator=(const std::vector<byte>&) = delete;
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;
};

} // namespace crypto

#endif

