#pragma once

#include "RegionStatistics.h"
#include "StandaloneBlocksStatistics.h"
#include "UncommittedRangesStatistics.h"
#include "RegionsSummary.h"

class HeapStatistics
{
private:
    static constexpr size_t kDefaultRegionsCapacity = 128;

    using RegionIterator = RegionsStatistics::iterator;

public:
    HeapStatistics(void* addr, ULONG info) : heapAddress(addr), heapInfo(info), lastUsedRegion(regions.end())
    {
        regions.reserve(kDefaultRegionsCapacity);
    }

    ~HeapStatistics() = default;

    HeapStatistics(const HeapStatistics& other) = delete;
    HeapStatistics(HeapStatistics&& other) = delete;

    HeapStatistics& operator=(const HeapStatistics& other) = delete;
    HeapStatistics& operator=(HeapStatistics&& other) = delete;

    bool HandleHeapEntry(const PROCESS_HEAP_ENTRY& entry);

    inline void Process()
    {
        for (auto& region : regions)
        {
            region->Process();
        }

        standaloneBlocks.Process();
        uncommittedRanges.Process();

        regionsSummary += regions;
        regionsSummary.Process();
    }

    WH_string ToString(bool includeRegions) const;

    inline void* GetHeapAddress() const
    {
        return heapAddress;
    }

    inline ULONG GetHeapInfo() const
    {
        return heapInfo;
    }

    inline const RegionsStatistics& GetRegionsStatistics() const
    {
        return regions;
    }

    inline const StandaloneBlocksStatistics& GetStandaloneBlocksStatistics() const
    {
        return standaloneBlocks;
    }

    inline const UncommittedRangesStatistics& GetUncommittedRangesStatistics() const
    {
        return uncommittedRanges;
    }

    inline const RegionsSummary& GetRegionsSummary() const
    {
        return regionsSummary;
    }

private:
    bool RegionExists(void* start, void* end) const;
    bool IsInRegion(RegionIterator region, void* addr) const;
    RegionIterator GetRegion(void* addr);

private:
    void* heapAddress = nullptr;
    ULONG heapInfo = 0;
    RegionsStatistics regions;
    StandaloneBlocksStatistics standaloneBlocks;
    UncommittedRangesStatistics uncommittedRanges;
    RegionsSummary regionsSummary;

    RegionIterator lastUsedRegion;
};

using HeapStatisticsPtr = WH_unique_ptr<HeapStatistics>;
using HeapsStatistics = WH_vector<HeapStatisticsPtr>;
