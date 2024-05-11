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
