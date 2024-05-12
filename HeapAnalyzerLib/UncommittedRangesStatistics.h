#pragma once

#include "FieldStatistics.h"
#include "Allocator.h"

#include <Windows.h>

#include <algorithm>

class UncommittedRangesStatistics
{
public:
    static constexpr size_t kFieldNameAlignment = std::max({
        sizeof("NumberOfRanges"),
        sizeof("Size"),
        sizeof("Overhead"),
        sizeof("SizeWithOverhead"),
    }) - 1 + FieldStatistics::kFieldNameAlignment;

public:
    UncommittedRangesStatistics() = default;
    ~UncommittedRangesStatistics() = default;

    UncommittedRangesStatistics(const UncommittedRangesStatistics& other) = delete;
    UncommittedRangesStatistics(UncommittedRangesStatistics&& other) = delete;

    UncommittedRangesStatistics& operator=(const UncommittedRangesStatistics& other) = delete;
    UncommittedRangesStatistics& operator=(UncommittedRangesStatistics&& other) = delete;

    inline UncommittedRangesStatistics& operator+=(const PROCESS_HEAP_ENTRY& range)
    {
        numberOfRanges++;
        size += static_cast<size_t>(range.cbData);
        overhead += static_cast<size_t>(range.cbOverhead);
        sizeWithOverhead += (static_cast<size_t>(range.cbData) + static_cast<size_t>(range.cbOverhead));

        return *this;
    }

    inline void Process()
    {
        size.Process(numberOfRanges);
        overhead.Process(numberOfRanges);
        sizeWithOverhead.Process(numberOfRanges);
    }

    WH_string ToString(size_t identation, const char* separator) const;

    size_t GetNumberOfRanges() const
    {
        return numberOfRanges;
    }

    const FieldStatistics& GetSize() const
    {
        return size;
    }

    const FieldStatistics& GetOverhead() const
    {
        return overhead;
    }

    const FieldStatistics& GetSizeWithOverhead() const
    {
        return sizeWithOverhead;
    }

private:
    size_t numberOfRanges = 0;

    FieldStatistics size;
    FieldStatistics overhead;
    FieldStatistics sizeWithOverhead;
};
