#ifndef COMMON_BYTE_BUFFER_H_
#define COMMON_BYTE_BUFFER_H_

#include <string>
#include <utility>
#include <vector>
#include <limits>
#include <iostream>

#include "common/common.h"

namespace crypto {

class ByteBuffer {
public:
    using const_iterator = std::vector<byte>::const_iterator;
    using iterator = std::vector<byte>::iterator;

    ByteBuffer() = default;

    ByteBuffer(const std::size_t n) {
        m_data.resize(n);
    }

    ByteBuffer(const std::initializer_list<byte>& il) {
        m_data.insert(m_data.end(), il.begin(), il.end());
    }

    ByteBuffer(const byte* begin, const byte* end) {
        m_data.insert(m_data.end(), begin, end);
    }

    ByteBuffer(ByteBuffer&& other) noexcept {
        *this = std::move(other);
    }

    ByteBuffer& operator=(ByteBuffer&& other) noexcept {
        m_data = std::move(other.m_data);
        return *this;
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        m_data.insert(end(), b.begin(), b.end());
        return *this;
    }

    ByteBuffer& operator+=(const byte b) {
        m_data.push_back(b);
        return *this;
    }

    const ByteBuffer operator+(const byte rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    const ByteBuffer operator+(const ByteBuffer& rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    friend const ByteBuffer operator+(const byte lhs, const ByteBuffer& rhs) {
        ByteBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    std::size_t size() const {
        return m_data.size();
    }

    const_iterator begin() const {
        return m_data.begin();
    }

    const_iterator end() const {
        return m_data.end();
    }

    byte& operator[](const std::size_t idx) {
        return m_data[idx];
    }

    const byte& operator[](const std::size_t idx) const {
        return m_data[idx];
    }

    bool operator==(const ByteBuffer& rhs) const {
        return size() == rhs.size() && std::equal(begin(), end(), rhs.begin());
    }

private:
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

    std::vector<byte> m_data;
};

} // namespace crypto

#endif

