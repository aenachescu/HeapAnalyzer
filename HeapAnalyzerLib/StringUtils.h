#pragma once

#include "Allocator.h"
#include "MinMax.h"

#include <iomanip>

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

template<typename T>
inline WH_string ToWHString(const T& val, bool addMeasurementUnit)
{
    static constexpr size_t kb = 1024;
    static constexpr size_t mb = kb * 1024;
    static constexpr size_t gb = mb * 1024;

    WH_ostringstream ss;
    ss << val;

    if (addMeasurementUnit == true && val >= kb)
    {
        double v = 0.0;
        const char* unit = "kb";

        if (val >= gb)
        {
            v = val / static_cast<double>(gb);
            unit = "gb";
        }
        else if (val >= mb)
        {
            v = val / static_cast<double>(mb);
            unit = "mb";
        }
        else
        {
            v = val / static_cast<double>(kb);
        }

        ss << '(' << std::fixed << std::setprecision(2) << v << unit << ')';
    }

    return ss.str();
}

template<MinMaxConcept T>
WH_string ToWHString(T& val, bool addMeasurementUnit, const WH_string& text, size_t identation = 0, const char* counterText = " Count: ")
{
    WH_string result(identation, ' ');
    result += text;
    result += val.getCounter() > 0 ? ToWHString(val.getValue(), addMeasurementUnit) : "NaN";
    result += counterText;
    result += ToWHString(val.getCounter());

    return result;
}
