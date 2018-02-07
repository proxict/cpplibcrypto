#ifndef COMMON_EXCEPTION_H_
#define COMMON_EXCEPTION_H_

#include <string>

namespace crypto {

/// Object expected to be thrown
///
/// Holds an error message in string format. This message is being dynamically allocated which means this object is not
/// suitable for throwing in situations where memory allocation is failing due its low state
class Exception {
public:
    Exception(const std::string& str) : m_str(str) {}

    /// Returns a reference to the message telling what went wrong
    virtual const std::string& what() const throw() { return m_str; }

private:
    const std::string m_str;
};

} // namespace crypto

#endif
