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
    WH_string res;
    std::format_to(std::back_inserter(res), "{}", val);
    return res;
}

template<typename T>
inline WH_string ToString(const T& val, bool addMeasurementUnit)
{
    static constexpr size_t kb = 1024;
    static constexpr size_t mb = kb * 1024;
    static constexpr size_t gb = mb * 1024;

    if (val < kb)
    {
        addMeasurementUnit = false;
    }

    if (addMeasurementUnit == false)
    {
        return ToString(val);
    }

    WH_string res;
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

    std::format_to(std::back_inserter(res), "{}({.2f}{})", val, v, unit);

    return res;
}

template<MinMaxConcept T>
WH_string ToString(T& val, bool addMeasurementUnit, const char* counterText = " Count: ")
{
    WH_string res;
    std::format_to(std::back_inserter(res), "{}{}{}",
        val.getCounter() > 0 ? ToString(val.getValue(), addMeasurementUnit) : "NaN",
        counterText,
        ToString(val.getCounter()));
    return res;
}

WH_string ToString(const PROCESS_HEAP_ENTRY& heapEntry);
