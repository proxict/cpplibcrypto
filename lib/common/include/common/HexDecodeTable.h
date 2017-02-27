#ifndef COMMON_HEX_DECODE_TABLE_H_
#define COMMON_HEX_DECODE_TABLE_H_

#include <stdexcept>

#include "common/common.h"

namespace crypto {

class HexDecodeTable {
public:
    constexpr HexDecodeTable() : m_tab {} {
        m_tab['1'] = 1;
        m_tab['2'] = 2;
        m_tab['3'] = 3;
        m_tab['4'] = 4;
        m_tab['5'] = 5;
        m_tab['6'] = 6;
        m_tab['7'] = 7;
        m_tab['8'] = 8;
        m_tab['9'] = 9;
        m_tab['a'] = 10;
        m_tab['A'] = 10;
        m_tab['b'] = 11;
        m_tab['B'] = 11;
        m_tab['c'] = 12;
        m_tab['C'] = 12;
        m_tab['d'] = 13;
        m_tab['D'] = 13;
        m_tab['e'] = 14;
        m_tab['E'] = 14;
        m_tab['f'] = 15;
        m_tab['F'] = 15;
    }
    constexpr byte hex2byte(const byte h, const byte l) const {
        if (!isValid(h) || !isValid(l)) {
            throw std::invalid_argument("Invalid HEX char passed");
        }
        return m_tab[h] << 4 | m_tab[l];
    }

private:
    constexpr bool isValid(const byte c) const {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    byte m_tab[128];
};

} // namespace crypto

#endif

