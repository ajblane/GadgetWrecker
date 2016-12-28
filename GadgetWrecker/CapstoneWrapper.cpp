

#include "CapstoneWrapper.hpp"

// To lazy to build capstone myself, solve some lib problems here...
int (WINAPIV * __vsnprintf)(char *, size_t, const char*, va_list) = _vsnprintf;
int (WINAPIV* _sprintf)(char*, const char*, ...) = sprintf;