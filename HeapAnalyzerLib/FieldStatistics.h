#pragma once

#include "MinMax.h"
#include "MathUtils.h"

class FieldStatistics
{
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

private:
    size_t total = 0;
    size_t avg = 0;
    MinValueAndCount<> min;
    MaxValueAndCount<> max;
};
