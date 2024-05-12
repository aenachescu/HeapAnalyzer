#pragma once

#include "BlocksStatistics.h"
#include "Allocator.h"

#include <Windows.h>

#include <memory>
#include <algorithm>

class RegionStatistics
{
public:
    static constexpr size_t kFieldNameAlignment = std::max({
        sizeof("Start"),
        sizeof("End"),
        sizeof("Size"),
        sizeof("Overhead"),
        sizeof("SizeWithOverhead"),
        sizeof("CommittedMemory"),
        sizeof("UncommittedMemory"),
        sizeof("TotalMemory"),
    }) - 1;

public:
    RegionStatistics(const PROCESS_HEAP_ENTRY& region)
    {
        start = region.Region.lpFirstBlock;
        end = region.Region.lpLastBlock;

        size = static_cast<size_t>(region.cbData);
        overhead = static_cast<size_t>(region.cbOverhead);
        sizeWithOverhead = size + overhead;

        committedMemory = static_cast<size_t>(region.Region.dwCommittedSize);
        uncommittedMemory = static_cast<size_t>(region.Region.dwUnCommittedSize);
        totalMemory = committedMemory + uncommittedMemory;
    }

    ~RegionStatistics() = default;

    RegionStatistics(const RegionStatistics& other) = delete;
    RegionStatistics(RegionStatistics&& other) = delete;

    RegionStatistics& operator=(const RegionStatistics& other) = delete;
    RegionStatistics& operator=(RegionStatistics&& other) = delete;

    inline RegionStatistics& operator+=(const PROCESS_HEAP_ENTRY& block)
    {
        if ((block.wFlags & PROCESS_HEAP_ENTRY_BUSY) == PROCESS_HEAP_ENTRY_BUSY)
        {
            used += block;
        }
        else
        {
            free += block;
        }

        total += block;

        return *this;
    }

    inline void Process()
    {
        total.Process();
        used.Process();
        free.Process();
    }

    WH_string ToString(size_t identation, const char* separator) const;

    inline void* GetStart() const
    {
        return start;
    }

    inline void* GetEnd() const
    {
        return end;
    }

    inline size_t GetSize() const
    {
        return size;
    }

    inline size_t GetOverhead() const
    {
        return overhead;
    }

    inline size_t GetSizeWithOverhead() const
    {
        return sizeWithOverhead;
    }

    inline size_t GetCommittedMemory() const
    {
        return committedMemory;
    }

    inline size_t GetUncommittedMemory() const
    {
        return uncommittedMemory;
    }

    inline size_t GetTotalMemory() const
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
    void* start = nullptr;
    void* end = nullptr;

    size_t size = 0;
    size_t overhead = 0;
    size_t sizeWithOverhead = 0;

    size_t committedMemory = 0;
    size_t uncommittedMemory = 0;
    size_t totalMemory = 0;

    BlocksStatistics total{ BlocksStatistics::Type::Total };
    BlocksStatistics used{ BlocksStatistics::Type::Used };
    BlocksStatistics free{ BlocksStatistics::Type::Free };
};

using RegionStatisticsPtr = WH_unique_ptr<RegionStatistics>;
using RegionsStatistics = WH_vector<RegionStatisticsPtr>;
