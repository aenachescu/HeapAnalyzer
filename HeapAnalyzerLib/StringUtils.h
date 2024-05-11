#pragma once

#include "Allocator.h"
#include "MinMax.h"

#include <iomanip>

template<typename T>
concept MinMaxConcept = requires(T a)
{
    a.getValue();
    a.getCounter();
};

template<typename T>
inline WH_string ToString(const T& val)
{
    WH_ostringstream ss;
    ss << val;
    return ss.str();
}

template<typename T>
inline WH_string ToString(const T& val, bool addMeasurementUnit)
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
WH_string ToString(T& val, bool addMeasurementUnit, const char* counterText = " Count: ")
{
    WH_string result = val.getCounter() > 0 ? ToString(val.getValue(), addMeasurementUnit) : "NaN";
    result += counterText;
    result += ToString(val.getCounter());

    return result;
}

WH_string ToString(const PROCESS_HEAP_ENTRY& heapEntry);
