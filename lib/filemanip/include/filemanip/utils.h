#ifndef FILEMANIP_UTILS_H_
#define FILEMANIP_UTILS_H_

#include <fstream>

#include "common/Exception.h"
#include "common/common.h"

namespace crypto {

/**
 * \brief fileExists check for file existence
 * \param filename filename to be checked
 * \return true if file exists, false otherwise
 */
inline bool fileExists(const std::string& filename) {
    std::ifstream stream(filename);
    return stream.good();
}

/**
 * \brief getFileSize returns file size in bytes
 * \param filename input filename
 * \return file size in bytes
 */
inline Size getFileSize(const std::string& filename) {
    std::ifstream stream(filename, std::ios::binary | std::ios::ate);
    if (!stream.is_open()) throw crypto::Exception("Could not open the file specified (" + filename + ')');
    return stream.tellg();
}

} // namespace crypto

#endif
