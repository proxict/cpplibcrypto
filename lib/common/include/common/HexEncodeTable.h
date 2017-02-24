#ifndef COMMON_HEX_ENCODE_TABLE_H_
#define COMMON_HEX_ENCODE_TABLE_H_

#include "common/common.h"

namespace crypto {

class HexEncodeTable {
public:
    constexpr static const char* byte2char(const byte b) {
        return m_tab[b];
    }

private:
    constexpr static const char* m_tab[256] = {
        #include "hexEncodeTable.inl"
    };
};

} // namespace crypto

#endif

