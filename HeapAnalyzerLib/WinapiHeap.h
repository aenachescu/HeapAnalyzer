#pragma once

#include "MinMax.h"
#include "Allocator.h"

#include <Windows.h>

namespace WinapiHeap
{

struct HeapStats
{
    struct BlocksStats
    {
        size_t numberOfBlocks = 0;
        size_t totalSize = 0;
        size_t totalOverhead = 0;

        MinValueAndCount<> minBlockSize;
        MaxValueAndCount<> maxBlockSize;

        MinValueAndCount<> minBlockOverhead;
        MaxValueAndCount<> maxBlockOverhead;

        MinValueAndCount<> minBlockSizeWithOverhead;
        MaxValueAndCount<> maxBlockSizeWithOverhead;

        WH_string ToString(const char* blockName, size_t identation, const char* separator) const;
    };

    struct RegionStats
    {
        size_t regionStart = 0;
        size_t regionEnd = 0;
        size_t regionSize = 0;
        size_t regionOverhead = 0;
        size_t regionCommittedSize = 0;
        size_t regionUncommittedSize = 0;

        BlocksStats total;
        BlocksStats used;
        BlocksStats free;

        WH_string ToString(size_t identation, const char* separator) const;
    };

    struct RegionsSummary
    {
        size_t numberOfRegions = 0;
        size_t totalSize = 0;
        size_t totalOverhead = 0;
        size_t totalCommittedSize = 0;
        size_t totalUncommittedSize = 0;

        MinValueAndCount<> minRegionSize;
        MaxValueAndCount<> maxRegionSize;

        MinValueAndCount<> minRegionOverhead;
        MaxValueAndCount<> maxRegionOverhead;

        MinValueAndCount<> minRegionCommittedSize;
        MaxValueAndCount<> maxRegionCommittedSize;

        MinValueAndCount<> minRegionUncommittedSize;
        MaxValueAndCount<> maxRegionUncommittedSize;

        BlocksStats total;
        BlocksStats used;
        BlocksStats free;

        WH_string ToString(size_t identation, const char* separator) const;
    };

    struct BlocksWithoutRegionStats
    {
        BlocksStats total;
        BlocksStats used;
        BlocksStats free;

        WH_string ToString(size_t identation, const char* separator) const;
    };

    struct UncommittedRangeStats
    {
        size_t numberOfRanges = 0;
        size_t totalSize = 0;
        size_t totalOverhead = 0;

        MinValueAndCount<> minRangeSize;
        MaxValueAndCount<> maxRangeSize;

        MinValueAndCount<> minRangeOverhead;
        MaxValueAndCount<> maxRangeOverhead;

        MinValueAndCount<> minRangeSizeWithOverhead;
        MaxValueAndCount<> maxRangeSizeWithOverhead;

        WH_string ToString(size_t identation, const char* separator) const;
    };

    using RegionsStats = WH_vector<RegionStats>;

    PVOID heapAddress = NULL;
    ULONG heapInfo = 0;
    RegionsSummary regionsSummary;
    UncommittedRangeStats uncommittedRangeStats;
    BlocksWithoutRegionStats bwrStats;
    RegionsStats regionsStats;

    WH_string ToString(bool includeRegions = false, const char* separator = "\n") const;
};

using HeapsStats = WH_vector<HeapStats>;

class HeapAnalyzer
{
public:
    HeapAnalyzer() = default;
    ~HeapAnalyzer() = default;

    bool GetHeapStatistics(HANDLE hHeap, bool bIsLocked, HeapStats& heapStats, bool generateAdditionalStats = true);
    bool GetHeapsStatistics(std::initializer_list<HANDLE> ignoredHeaps, HeapsStats& heapsStats);

private:
    WH_string HeapFlagsToString(WORD flags);
    WH_string HeapEntryToString(const PROCESS_HEAP_ENTRY& heapEntry);

    void UpdateBlocksStats(HeapStats::BlocksStats& blocksStats, const PROCESS_HEAP_ENTRY& heapEntry);

    void GenerateAdditionalHeapStats(HeapStats& heapStats);
    void GenerateRegionsSummary(HeapStats& heapStats);
    void MergeBlocksStats(HeapStats::BlocksStats& dst, const HeapStats::BlocksStats& src);

    bool RegionExists(const HeapStats& heapStats, const PROCESS_HEAP_ENTRY& entry);
    bool IsInRegion(const HeapStats& heapStats, HeapStats::RegionsStats::iterator region, const PROCESS_HEAP_ENTRY& heapEntry);
    HeapStats::RegionsStats::iterator GetRegion(HeapStats& heapStats, const PROCESS_HEAP_ENTRY& heapEntry);

    bool IsLockableHeap(HANDLE hHeap);
};

} // namespace WinapiHeap
