#ifndef FILEMANIP_BINARYFILE_H_
#define FILEMANIP_BINARYFILE_H_

#include <fstream>
#include <string>

#include "common/Exception.h"
#include "common/StaticBuffer.h"
#include "common/DynamicBuffer.h"

namespace crypto {

class BinaryFile {
    using StaticByteBufferBase = StaticBufferBase<Byte>;
public:
    enum class Mode { Read = 1, Write };
    BinaryFile(const std::string& filename, const Mode mode) :
        m_stream(filename, (mode == Mode::Read ? std::ios::in : std::ios::out) | std::ios::binary), m_mode(mode) {
        if (!m_stream.good()) {
            throw Exception("Could not open the file specified");
        }
    }

    template <typename TContainer>
    Size read(TContainer& output, const Size readMax) {
        ASSERT(m_mode == Mode::Read);
        ByteBuffer temp(readMax);
        m_stream.read(reinterpret_cast<char*>(temp.data()), temp.size());
        const Size bytesRead = static_cast<Size>(m_stream.gcount());

        output.reserve(bytesRead);
        output.insert(output.end(), temp.begin(), temp.begin() + bytesRead);

        return bytesRead;
    }

    template <typename TContainer>
    bool write(const TContainer& buffer) {
        ASSERT(m_mode == Mode::Write);
        return bool(m_stream.write(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

private:
    std::fstream m_stream;
    Mode m_mode;
};

} // namespace crypto

#endif

