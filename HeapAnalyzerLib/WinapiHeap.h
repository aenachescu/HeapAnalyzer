#pragma once

#include "MinMax.h"
#include "Allocator.h"

#include <Windows.h>

namespace WinapiHeap
{

struct BlocksStats
{
    size_t numberOfBlocks = 0;

    size_t totalSize = 0;
    size_t totalOverhead = 0;
    size_t totalSizeAndOverhead = 0;

    MinValueAndCount<> minBlockSize;
    MaxValueAndCount<> maxBlockSize;
    size_t avgBlockSize = 0;

    MinValueAndCount<> minBlockOverhead;
    MaxValueAndCount<> maxBlockOverhead;
    size_t avgBlockOverhead = 0;

    MinValueAndCount<> minBlockSizeWithOverhead;
    MaxValueAndCount<> maxBlockSizeWithOverhead;
    size_t avgBlockSizeAndOverhead = 0;

    WH_string ToString(const char* blockName, size_t identation, const char* separator) const;
};

struct RegionStats
{
    size_t regionStart = 0;
    size_t regionEnd = 0;

    size_t regionSize = 0;
    size_t regionOverhead = 0;
    size_t regionSizeAndOverhead = 0;

    size_t regionCommittedSize = 0;
    size_t regionUncommittedSize = 0;
    size_t regionCommittedAndUncommittedSize = 0;

    BlocksStats total;
    BlocksStats used;
    BlocksStats free;

    WH_string ToString(size_t identation, const char* separator) const;
};

using RegionsStats = WH_vector<RegionStats>;

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
    size_t totalSizeAndOverhead = 0;

    MinValueAndCount<> minRangeSize;
    MaxValueAndCount<> maxRangeSize;
    size_t avgRangeSize = 0;

    MinValueAndCount<> minRangeOverhead;
    MaxValueAndCount<> maxRangeOverhead;
    size_t avgRangeOverhead = 0;

    MinValueAndCount<> minRangeSizeWithOverhead;
    MaxValueAndCount<> maxRangeSizeWithOverhead;
    size_t avgRangeSizeWithOverhead = 0;

    WH_string ToString(size_t identation, const char* separator) const;
};

struct RegionsSummary
{
    size_t numberOfRegions = 0;

    size_t totalSize = 0;
    size_t totalOverhead = 0;
    size_t totalSizeAndOverhead = 0;

    size_t totalCommittedSize = 0;
    size_t totalUncommittedSize = 0;
    size_t totalCommittedAndUncommittedSize = 0;

    MinValueAndCount<> minRegionSize;
    MaxValueAndCount<> maxRegionSize;
    size_t avgRegionSize = 0;

    MinValueAndCount<> minRegionOverhead;
    MaxValueAndCount<> maxRegionOverhead;
    size_t avgRegionOverhead = 0;

    MinValueAndCount<> minRegionSizeWithOverhead;
    MaxValueAndCount<> maxRegionSizeWithOverhead;
    size_t avgRegionSizeWithOverhead = 0;

    MinValueAndCount<> minRegionCommittedSize;
    MaxValueAndCount<> maxRegionCommittedSize;
    size_t avgRegionCommittedSize = 0;

    MinValueAndCount<> minRegionUncommittedSize;
    MaxValueAndCount<> maxRegionUncommittedSize;
    size_t avgRegionUncommittedSize = 0;

    MinValueAndCount<> minRegionCommittedAndUncommittedSize;
    MaxValueAndCount<> maxRegionCommittedAndUncommittedSize;
    size_t avgRegionCommittedAndUncommittedSize = 0;

    BlocksStats total;
    BlocksStats used;
    BlocksStats free;

    WH_string ToString(size_t identation, const char* separator) const;
};

struct HeapStats
{
    PVOID heapAddress = NULL;
    ULONG heapInfo = 0;
    RegionsStats regionsStats;
    BlocksWithoutRegionStats bwrStats;
    UncommittedRangeStats uncommittedRangeStats;
    RegionsSummary regionsSummary;

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

    void UpdateBlocksStats(BlocksStats& blocksStats, const PROCESS_HEAP_ENTRY& heapEntry);

    void ProcessStats(BlocksStats& blockStats);
    void ProcessStats(RegionStats& regionStats);
    void ProcessStats(BlocksWithoutRegionStats& bwrStats);
    void ProcessStats(UncommittedRangeStats& rangeStats);

    void GenerateAdditionalHeapStats(HeapStats& heapStats);
    void GenerateRegionsSummary(HeapStats& heapStats);
    void MergeBlocksStats(BlocksStats& dst, const BlocksStats& src);

    bool RegionExists(const HeapStats& heapStats, const PROCESS_HEAP_ENTRY& entry);
    bool IsInRegion(const HeapStats& heapStats, RegionsStats::iterator region, const PROCESS_HEAP_ENTRY& heapEntry);
    RegionsStats::iterator GetRegion(HeapStats& heapStats, const PROCESS_HEAP_ENTRY& heapEntry);

    bool IsLockableHeap(HANDLE hHeap);
};

} // namespace WinapiHeap
