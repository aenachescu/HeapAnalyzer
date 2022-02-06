#pragma once

#include <vector>
#include <string>

#include "MinMax.h"
#include "Allocator.h"

#include <Windows.h>

namespace WinapiHeap
{

struct HeapStats
{
    struct BlocksStats
    {
        size_t num = 0;
        size_t size = 0;
        size_t overhead = 0;

        MinValueAndCount<> shortestBlock;
        MaxValueAndCount<> longestBlock;

        MinValueAndCount<> shortestOverhead;
        MaxValueAndCount<> longestOverhead;

        MinValueAndCount<> shortestBlockWithOverhead;
        MaxValueAndCount<> longestBlockWithOverhead;

        std::string ToString(const char* blockName, size_t identation, const char* separator) const;
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

        std::string ToString(size_t identation, const char* separator) const;
    };

    struct RegionsStats
    {
        size_t numberOfRegions = 0;
        size_t size = 0;
        size_t overhead = 0;
        size_t committedSize = 0;
        size_t uncommittedSize = 0;

        MaxValueAndCount<> longestSize;
        MinValueAndCount<> shortestSize;
        MaxValueAndCount<> longestOverhead;
        MinValueAndCount<> shortestOverhead;
        MaxValueAndCount<> longestCommittedSize;
        MinValueAndCount<> shortestCommittedSize;
        MaxValueAndCount<> longestUncommittedSize;
        MinValueAndCount<> shortestUncommittedSize;

        BlocksStats total;
        BlocksStats used;
        BlocksStats free;

        std::string ToString(size_t identation, const char* separator) const;
    };

    struct BlocksWithoutRegionStats
    {
        BlocksStats total;
        BlocksStats used;
        BlocksStats free;

        std::string ToString(size_t identation, const char* separator) const;
    };

    struct UncommittedRangeStats
    {
        size_t numOfRanges = 0;
        size_t totalSize = 0;

        MinValueAndCount<> shortestRange;
        MaxValueAndCount<> longestRange;

        MaxValue<> longestOverhead;
        MaxValue<> biggestRegionIndex;

        std::string ToString(size_t identation, const char* separator) const;
    };

    using Regions = std::vector<RegionStats, WorkingHeapAllocator<RegionStats>>;

    PVOID heapAddress = NULL;
    ULONG heapInfo = 0;
    RegionsStats regionsStats;
    UncommittedRangeStats uncommittedRangeStats;
    BlocksWithoutRegionStats bwrStats;
    Regions regions;

    std::string ToString(bool includeRegions = false, const char* separator = "\n") const;
};

using HeapsStats = std::vector<HeapStats, WorkingHeapAllocator<HeapStats>>;

class HeapAnalyzer
{
public:
    HeapAnalyzer() = default;
    ~HeapAnalyzer() = default;

    bool GetHeapStatistics(HANDLE hHeap, bool bIsLocked, HeapStats& heapStats);
    bool GetHeapsStatistics(std::initializer_list<HANDLE> ignoredHeaps, HeapsStats& heapsStats);

private:
    std::string HeapFlagsToString(WORD flags);
    std::string HeapEntryToString(const PROCESS_HEAP_ENTRY& heapEntry);

    void UpdateBlocksStats(HeapStats::BlocksStats& blocksStats, const PROCESS_HEAP_ENTRY& heapEntry);
    void GenerateRegionsStats(HeapStats& heapStats);
    void MergeBlocksStats(HeapStats::BlocksStats& dst, const HeapStats::BlocksStats& src);

    bool RegionExists(const HeapStats& heapStats, const PROCESS_HEAP_ENTRY& entry);
    bool IsInRegion(const HeapStats& heapStats, HeapStats::Regions::iterator region, const PROCESS_HEAP_ENTRY& heapEntry);
    HeapStats::Regions::iterator GetRegion(HeapStats& heapStats, const PROCESS_HEAP_ENTRY& heapEntry);

    bool IsLockableHeap(HANDLE hHeap);
};

} // namespace WinapiHeap
