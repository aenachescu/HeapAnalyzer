#pragma once

#include "FieldStatistics.h"
#include "BlocksStatistics.h"
#include "RegionStatistics.h"
#include "Allocator.h"

#include <Windows.h>

#include <algorithm>

class RegionsSummary
{
public:
    static constexpr size_t kFieldNameAlignment = std::max({
        sizeof("NumberOfRegions"),
        sizeof("Size"),
        sizeof("Overhead"),
        sizeof("SizeWithOverhead"),
        sizeof("CommittedMemory"),
        sizeof("UncommittedMemory"),
        sizeof("TotalMemory"),
    }) - 1 + FieldStatistics::kFieldNameAlignment;

public:
    RegionsSummary() = default;
    ~RegionsSummary() = default;

    RegionsSummary(const RegionsSummary& other) = delete;
    RegionsSummary(RegionsSummary&& other) = delete;

    RegionsSummary& operator=(const RegionsSummary& other) = delete;
    RegionsSummary& operator=(RegionsSummary&& other) = delete;

    inline RegionsSummary& operator+=(const RegionStatistics& region)
    {
        numberOfRegions++;

        size += region.GetSize();
        overhead += region.GetOverhead();
        sizeWithOverhead += region.GetSizeWithOverhead();

        committedMemory += region.GetCommittedMemory();
        uncommittedMemory += region.GetUncommittedMemory();
        totalMemory += region.GetTotalMemory();

        total += region.GetTotalBlocksStatistics();
        used += region.GetUsedBlocksStatistics();
        free += region.GetFreeBlocksStatistics();

        return *this;
    }

    inline RegionsSummary& operator+=(const RegionsStatistics& regions)
    {
        for (const auto& region : regions)
        {
            *this += *region;
        }

        return *this;
    }

    inline void Process()
    {
        size.Process(numberOfRegions);
        overhead.Process(numberOfRegions);
        sizeWithOverhead.Process(numberOfRegions);

        committedMemory.Process(numberOfRegions);
        uncommittedMemory.Process(numberOfRegions);
        totalMemory.Process(numberOfRegions);

        total.Process();
        used.Process();
        free.Process();
    }

    WH_string ToString(size_t identation, const char* separator) const;

    inline size_t GetNumberOfRegions() const
    {
        return numberOfRegions;
    }

    inline const FieldStatistics& GetSize() const
    {
        return size;
    }

    inline const FieldStatistics& GetOverhead() const
    {
        return overhead;
    }

    inline const FieldStatistics& GetSizeWithOverhead() const
    {
        return sizeWithOverhead;
    }

    inline const FieldStatistics& GetCommittedMemory() const
    {
        return committedMemory;
    }

    inline const FieldStatistics& GetUncommittedMemory() const
    {
        return uncommittedMemory;
    }

    inline const FieldStatistics& GetTotalMemory() const
    {
        return totalMemory;
    }

    inline const BlocksStatistics& GetTotalBlocksStatistics() const
    {
        return total;
    }

    inline const BlocksStatistics& GetUsedBlocksStatistics() const
    {
        return used;
    }

    inline const BlocksStatistics& GetFreeBlocksStatistics() const
    {
        return free;
    }

private:
    size_t numberOfRegions = 0;

    FieldStatistics size;
    FieldStatistics overhead;
    FieldStatistics sizeWithOverhead;

    FieldStatistics committedMemory;
    FieldStatistics uncommittedMemory;
    FieldStatistics totalMemory;

    BlocksStatistics total{ BlocksStatistics::Type::Total };
    BlocksStatistics used{ BlocksStatistics::Type::Used };
    BlocksStatistics free{ BlocksStatistics::Type::Free };
};
