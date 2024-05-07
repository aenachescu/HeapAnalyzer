#pragma once

#include "Allocator.h"
#include "MinMax.h"

inline WH_string NormalizeFieldName(const char* fieldName, size_t maxFieldName)
{
    WH_string result = fieldName;
    result.append(maxFieldName - result.size(), ' ');
    result += " : ";

    return result;
}

template<typename T>
concept MinMaxConcept = requires(T a)
{
    a.getValue();
    a.getCounter();
};

template<typename T>
inline WH_string ToWHString(const T& val)
{
    WH_ostringstream ss;
    ss << val;
    return ss.str();
}

template<MinMaxConcept T>
WH_string ToWHString(T& val, const WH_string& text, size_t identation = 0, const char* counterText = " Count: ")
{
    WH_string result(identation, ' ');
    result += text;
    result += val.getCounter() > 0 ? ToWHString(val.getValue()) : "NaN";
    result += counterText;
    result += ToWHString(val.getCounter());

    return result;
}
