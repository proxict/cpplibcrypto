#ifndef COMMON_FIXEDSIZEBUFFER_H_
#define COMMON_FIXEDSIZEBUFFER_H_

#include <limits>
#include <utility>
#include <vector>

#include "common/common.h"

namespace crypto {

template <std::size_t size>
class FixedSizeBuffer {
public:
    FixedSizeBuffer(const bool sensitive = true) : m_sensitiveData(sensitive) {}

    FixedSizeBuffer(std::initializer_list<byte>&& list, const bool sensitive = true) : m_sensitiveData(sensitive), m_data(std::move(list)) {}

    FixedSizeBuffer& operator=(FixedSizeBuffer&& other) noexcept {
        m_data = std::move(other.m_data);
        return *this;
    }

    FixedSizeBuffer(FixedSizeBuffer&& other) noexcept {
        *this = std::move(other);
    }

    const byte* begin() const {
        return m_data;
    }

    const byte* end() const {
        return &m_data[size];
    }

    byte& operator[](std::size_t index) {
        return m_data[index];
    }

    FixedSizeBuffer& operator+=(const FixedSizeBuffer& b) {
        m_data.insert(m_data.end(), b.m_data.begin(), b.m_data.end());
        return *this;
    }

    FixedSizeBuffer& operator+=(const byte b) {
        m_data.push_back(b);
        return *this;
    }

    const FixedSizeBuffer operator+(const FixedSizeBuffer& rhs) const {
        FixedSizeBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    const FixedSizeBuffer operator+(const byte rhs) const {
        FixedSizeBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    friend const FixedSizeBuffer operator+(const byte lhs, const FixedSizeBuffer& rhs) {
        FixedSizeBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    bool operator==(const FixedSizeBuffer& rhs) const {
        return m_data.size() == rhs.m_data.size() && std::equal(m_data.begin(), m_data.end(), rhs.m_data.begin());
    }

    bool operator!=(const FixedSizeBuffer& rhs) const {
        return !(*this == rhs);
    }

private:
    FixedSizeBuffer(const FixedSizeBuffer&) = delete;
    FixedSizeBuffer& operator=(const FixedSizeBuffer&) = delete;

    bool m_sensitiveData;
    byte m_data[size];
};

} // namespace crypto

#endif // COMMON_BYTEBUFFER_H_
