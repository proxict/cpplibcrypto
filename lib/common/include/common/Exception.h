#ifndef COMMON_EXCEPTION_H_
#define COMMON_EXCEPTION_H_

#include <string>

class Exception {
public:
    Exception(const std::string& str) : m_str(str) {}
    virtual const std::string what() const throw() {
        return m_str;
    }

private:
    const std::string m_str;
};

#endif

