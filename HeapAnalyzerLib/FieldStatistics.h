#pragma once

#include "MinMax.h"
#include "MathUtils.h"
#include "StringUtils.h"

#include <algorithm>

class FieldStatistics
{
public:
    static constexpr size_t kFieldNameAlignment = std::max({
        sizeof("Total"),
        sizeof("Avg"),
        sizeof("Min"),
        sizeof("Max"),
    }) - 1;

public:
    FieldStatistics() = default;
    ~FieldStatistics() = default;

    FieldStatistics(const FieldStatistics& other) = delete;
    FieldStatistics(FieldStatistics&& other) = delete;

    FieldStatistics& operator=(const FieldStatistics& other) = delete;
    FieldStatistics& operator=(FieldStatistics&& other) = delete;

    inline FieldStatistics& operator+=(const FieldStatistics& other)
    {
        total += other.total;
        min = other.min;
        max = other.max;

        return *this;
    }

    inline FieldStatistics& operator+=(size_t val)
    {
        total += val;
        min = val;
        max = val;

        return *this;
    }

    inline void Process(size_t num)
    {
        avg = Avg(total, num);
    }

    WH_string ToString(size_t identation, const char* separator, const char* name, size_t alignment) const
    {
        WH_string res;

        std::format_to(
            std::back_inserter(res),
            "{:{}}{}{:{}} : {}{}",
            ' ', identation,
            "Total",
            name, alignment - (sizeof("Total") - 1),
            ::ToString(total, true),
            separator);

        std::format_to(
            std::back_inserter(res),
            "{:{}}{}{:{}} : {}{}",
            ' ', identation,
            "Avg",
            name, alignment - (sizeof("Avg") - 1),
            ::ToString(avg, true),
            separator);

        std::format_to(
            std::back_inserter(res),
            "{:{}}{}{:{}} : {}{}",
            ' ', identation,
            "Min",
            name, alignment - (sizeof("Min") - 1),
            ::ToString(min, true),
            separator);

        std::format_to(
            std::back_inserter(res),
            "{:{}}{}{:{}} : {}",
            ' ', identation,
            "Max",
            name, alignment - (sizeof("Max") - 1),
            ::ToString(max, true));

        return res;
    }

    inline size_t GetTotal() const
    {
        return total;
    }

    inline size_t GetAvg() const
    {
        return avg;
    }

    inline const MinValueAndCount& GetMin() const
    {
        return min;
    }

    inline const MaxValueAndCount& GetMax() const
    {
        return max;
    }

private:
    size_t total = 0;
    size_t avg = 0;
    MinValueAndCount min;
    MaxValueAndCount max;
};
