#ifndef FILEMANIP_UTILS_H_
#define FILEMANIP_UTILS_H_

#include <fstream>

#include "common/Exception.h"
#include "common/common.h"

namespace crypto {

/// Returns whether or not the file specified exists
inline bool fileExists(const std::string& filename) {
    std::ifstream stream(filename);
    return stream.good();
}

/// Returns the size of the file specified
inline Size getFileSize(const std::string& filename) {
    std::ifstream stream(filename, std::ios::binary | std::ios::ate);
    if (!stream.is_open()) throw crypto::Exception("Could not open the file specified (" + filename + ')');
    return stream.tellg();
}

} // namespace crypto

#endif
