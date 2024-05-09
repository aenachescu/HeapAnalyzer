#pragma once

#include "FieldStatistics.h"
#include "BlocksStatistics.h"
#include "RegionStatistics.h"
#include "Allocator.h"

#include <Windows.h>

class RegionsSummary
{
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
