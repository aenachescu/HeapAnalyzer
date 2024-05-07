#include "pch.h"
#include "WinapiHeap.h"
#include "Logger.h"
#include "StringUtils.h"
#include "Settings.h"

#include <algorithm>
#include <ranges>

extern Logger g_logger;

namespace WinapiHeap
{

static WH_string HeapInfoToStr(ULONG info)
{
    static constexpr ULONG kStandard = 0;
    static constexpr ULONG kLookAsideLists = 1;
    static constexpr ULONG kLowFragmentation = 2;

    switch (info)
    {
    case kStandard:
        return "Standard";
    case kLookAsideLists:
        return "LookAsideLists";
    case kLowFragmentation:
        return "LowFragmentation";
    default:
        break;
    }

    return ToWHString(info);
}

WH_string HeapStats::BlocksStats::ToString(const char* blockName, size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("NumberOfBlocks"),
        sizeof("TotalSize"),
        sizeof("TotalOverhead"),
        sizeof("TotalSizeAndOverhead"),
        sizeof("MinBlockSize"),
        sizeof("MaxBlockSize"),
        sizeof("MinBlockOverhead"),
        sizeof("MaxBlockOverhead"),
        sizeof("MinBlockSizeWithOverhead"),
        sizeof("MaxBlockSizeWithOverhead"),
    }) - 1;

    WH_string result;
    WH_string identationStr = WH_string(identation, ' ');

    result += identationStr + "Blocks stats - " + blockName + separator;

    identation += 4;
    identationStr = WH_string(identation, ' ');

    result += identationStr + NormalizeFieldName("NumberOfBlocks", kMaxFieldName) + ToWHString(numberOfBlocks) + separator;
    result += identationStr + NormalizeFieldName("TotalSize", kMaxFieldName) + ToWHString(totalSize) + separator;
    result += identationStr + NormalizeFieldName("TotalOverhead", kMaxFieldName) + ToWHString(totalOverhead) + separator;
    result += identationStr + NormalizeFieldName("TotalSizeAndOverhead", kMaxFieldName) + ToWHString(totalSize + totalOverhead) + separator;

    result += ToWHString(minBlockSize, NormalizeFieldName("MinBlockSize", kMaxFieldName), identation) + separator;
    result += ToWHString(maxBlockSize, NormalizeFieldName("MaxBlockSize", kMaxFieldName), identation) + separator;
    result += ToWHString(minBlockOverhead, NormalizeFieldName("MinBlockOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(maxBlockOverhead, NormalizeFieldName("MaxBlockOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(minBlockSizeWithOverhead, NormalizeFieldName("MinBlockSizeWithOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(maxBlockSizeWithOverhead, NormalizeFieldName("MaxBlockSizeWithOverhead", kMaxFieldName), identation) + separator;

    return result;
}

WH_string HeapStats::RegionStats::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Start"),
        sizeof("End"),
        sizeof("Size"),
        sizeof("Overhead"),
        sizeof("CommittedSize"),
        sizeof("UncommittedSize"),
    }) - 1;

    WH_string result;
    WH_string identationStr = WH_string(identation, ' ');

    result += identationStr + NormalizeFieldName("Start", kMaxFieldName) +
        ToWHString(reinterpret_cast<void*>(regionStart)) + separator;
    result += identationStr + NormalizeFieldName("End", kMaxFieldName) +
        ToWHString(reinterpret_cast<void*>(regionEnd)) + separator;
    result += identationStr + NormalizeFieldName("Size", kMaxFieldName) + ToWHString(regionSize) + separator;
    result += identationStr + NormalizeFieldName("Overhead", kMaxFieldName) + ToWHString(regionOverhead) + separator;
    result += identationStr + NormalizeFieldName("CommittedSize", kMaxFieldName) + ToWHString(regionCommittedSize) + separator;
    result += identationStr + NormalizeFieldName("UncommittedSize", kMaxFieldName) + ToWHString(regionUncommittedSize) + separator;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

WH_string HeapStats::RegionsSummary::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("NumberOfRegions"),
        sizeof("TotalSize"),
        sizeof("TotalOverhead"),
        sizeof("TotalSizeAndOverhead"),
        sizeof("TotalCommittedSize"),
        sizeof("TotalUncommittedSize"),
        sizeof("MinRegionSize"),
        sizeof("MaxRegionSize"),
        sizeof("MinRegionOverhead"),
        sizeof("MaxRegionOverhead"),
        sizeof("MinRegionCommittedSize"),
        sizeof("MaxRegionCommittedSize"),
        sizeof("MinRegionUncommittedSize"),
        sizeof("MaxRegionUncommittedSize"),
    }) - 1;

    WH_string result;
    WH_string identationStr = WH_string(identation, ' ');

    result += identationStr + NormalizeFieldName("NumberOfRegions", kMaxFieldName) + ToWHString(numberOfRegions) + separator;
    result += identationStr + NormalizeFieldName("TotalSize", kMaxFieldName) + ToWHString(totalSize) + separator;
    result += identationStr + NormalizeFieldName("TotalOverhead", kMaxFieldName) + ToWHString(totalOverhead) + separator;
    result += identationStr + NormalizeFieldName("TotalSizeAndOverhead", kMaxFieldName) + ToWHString(totalSize + totalOverhead) + separator;
    result += identationStr + NormalizeFieldName("TotalCommittedSize", kMaxFieldName) + ToWHString(totalCommittedSize) + separator;
    result += identationStr + NormalizeFieldName("TotalUncommittedSize", kMaxFieldName) + ToWHString(totalUncommittedSize) + separator;

    result += ToWHString(minRegionSize, NormalizeFieldName("MinRegionSize", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRegionSize, NormalizeFieldName("MaxRegionSize", kMaxFieldName), identation) + separator;
    result += ToWHString(minRegionOverhead, NormalizeFieldName("MinRegionOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRegionOverhead, NormalizeFieldName("MaxRegionOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(minRegionCommittedSize, NormalizeFieldName("MinRegionCommittedSize", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRegionCommittedSize, NormalizeFieldName("MaxRegionCommittedSize", kMaxFieldName), identation) + separator;
    result += ToWHString(minRegionUncommittedSize, NormalizeFieldName("MinRegionUncommittedSize", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRegionUncommittedSize, NormalizeFieldName("MaxRegionUncommittedSize", kMaxFieldName), identation) + separator;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

WH_string HeapStats::BlocksWithoutRegionStats::ToString(size_t identation, const char* separator) const
{
    WH_string result;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

WH_string HeapStats::UncommittedRangeStats::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("NumberOfRanges"),
        sizeof("TotalSize"),
        sizeof("TotalOverhead"),
        sizeof("TotalSizeAndOverhead"),
        sizeof("MinRangeSize"),
        sizeof("MaxRangeSize"),
        sizeof("MinRangeOverhead"),
        sizeof("MaxRangeOverhead"),
        sizeof("MinRangeSizeWithOverhead"),
        sizeof("MaxRangeSizeWithOverhead"),
    }) - 1;

    WH_string result;
    WH_string identationStr = WH_string(identation, ' ');

    result += identationStr + NormalizeFieldName("NumberOfRanges", kMaxFieldName) + ToWHString(numberOfRanges) + separator;
    result += identationStr + NormalizeFieldName("TotalSize", kMaxFieldName) + ToWHString(totalSize) + separator;
    result += identationStr + NormalizeFieldName("TotalOverhead", kMaxFieldName) + ToWHString(totalOverhead) + separator;
    result += identationStr + NormalizeFieldName("TotalSizeAndOverhead", kMaxFieldName) + ToWHString(totalSize + totalOverhead) + separator;

    result += ToWHString(minRangeSize, NormalizeFieldName("MinRangeSize", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRangeSize, NormalizeFieldName("MaxRangeSize", kMaxFieldName), identation) + separator;
    result += ToWHString(minRangeOverhead, NormalizeFieldName("MinRangeOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRangeOverhead, NormalizeFieldName("MaxRangeOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(minRangeSizeWithOverhead, NormalizeFieldName("MinRangeSizeWithOverhead", kMaxFieldName), identation) + separator;
    result += ToWHString(maxRangeSizeWithOverhead, NormalizeFieldName("MaxRangeSizeWithOverhead", kMaxFieldName), identation) + separator;

    return result;
}

WH_string HeapStats::ToString(bool includeRegions, const char* separator) const
{
    WH_string result;
    bool bFirstRegion = true;

    result += "Heap: " + ToWHString(reinterpret_cast<void*>(heapAddress)) + separator;
    result += "Info: " + HeapInfoToStr(heapInfo) + separator;

    result += "Regions summary:";
    result += separator;
    result += regionsSummary.ToString(4, separator);

    result += "Uncommitted range stats:";
    result += separator;
    result += uncommittedRangeStats.ToString(4, separator);

    if (bwrStats.total.numberOfBlocks == 0)
    {
        result += "Blocks without regions: empty";
        result += separator;
    }
    else
    {
        result += "Blocks without regions:";
        result += separator;
        result += bwrStats.ToString(4, separator);
    }

    if (includeRegions == true)
    {
        result += "Regions:";
        result += separator;
        for (const auto& r : regionsStats)
        {
            if (bFirstRegion == true)
                bFirstRegion = false;
            else
                result += "    " + WH_string(50, '-') + separator;

            result += r.ToString(4, separator);
        }
    }

    return result;
}

bool HeapAnalyzer::GetHeapStatistics(HANDLE hHeap, bool bIsLocked, HeapStats& heapStats, bool generateAdditionalStats)
{
    extern Settings g_settings;

    g_logger.LogInfo("GetHeapStatistics: {} {}", hHeap, bIsLocked);

    if (bIsLocked == false)
    {
        if (IsLockableHeap(hHeap) == false)
        {
            g_logger.LogError("Heap is not lockable", GetLastError());
            return false;
        }

        if (HeapValidate(hHeap, 0, NULL) == FALSE)
        {
            g_logger.LogError("Failed to validate heap: {}", GetLastError());
            return false;
        }

        auto locked = HeapLock(hHeap);
        if (locked == FALSE)
        {
            g_logger.LogError("Failed to lock heap: {}", GetLastError());
            return false;
        }
    }
    else
    {
        if (HeapValidate(hHeap, HEAP_NO_SERIALIZE, NULL) == FALSE)
        {
            g_logger.LogError("Failed to validate heap: {}", GetLastError());
            return false;
        }
    }

    bool bRes = true;
    BOOL bWinRes = FALSE;
    PROCESS_HEAP_ENTRY heapEntry;
    auto lastUsedRegion = heapStats.regionsStats.end();

    heapEntry.lpData = NULL;

    heapStats.heapAddress = hHeap;

    bWinRes = HeapQueryInformation(hHeap, HeapCompatibilityInformation, &heapStats.heapInfo, sizeof(heapStats.heapInfo), NULL);
    if (bWinRes == FALSE)
    {
        g_logger.LogError("Failed to get heap info: {}", GetLastError());
        bRes = false;
        goto end;
    }

    while (HeapWalk(hHeap, &heapEntry) != FALSE)
    {
        if (g_settings.bHeapEntryLogging == true)
            g_logger.LogInfo("Processing heap entry:\n{}", HeapEntryToString(heapEntry));

        if (heapEntry.wFlags == PROCESS_HEAP_UNCOMMITTED_RANGE)
        {
            size_t rangeSizeWithOverhead = static_cast<size_t>(heapEntry.cbData) + heapEntry.cbOverhead;

            heapStats.uncommittedRangeStats.numberOfRanges += 1;
            heapStats.uncommittedRangeStats.totalSize += heapEntry.cbData;

            heapStats.uncommittedRangeStats.minRangeSize = heapEntry.cbData;
            heapStats.uncommittedRangeStats.maxRangeSize = heapEntry.cbData;

            heapStats.uncommittedRangeStats.minRangeOverhead = heapEntry.cbOverhead;
            heapStats.uncommittedRangeStats.maxRangeOverhead = heapEntry.cbOverhead;

            heapStats.uncommittedRangeStats.minRangeSizeWithOverhead = rangeSizeWithOverhead;
            heapStats.uncommittedRangeStats.maxRangeSizeWithOverhead = rangeSizeWithOverhead;

            continue;
        }

        if (heapEntry.wFlags == PROCESS_HEAP_REGION)
        {
            if (RegionExists(heapStats, heapEntry) == true)
            {
                g_logger.LogError("Region already exists:\n{}", HeapEntryToString(heapEntry));
                bRes = false;
                break;
            }

            HeapStats::RegionStats reg;

            reg.regionStart = reinterpret_cast<size_t>(heapEntry.lpData);
            reg.regionEnd = reinterpret_cast<size_t>(heapEntry.Region.lpLastBlock);
            reg.regionSize = heapEntry.cbData;
            reg.regionOverhead = heapEntry.cbOverhead;
            reg.regionCommittedSize = heapEntry.Region.dwCommittedSize;
            reg.regionUncommittedSize = heapEntry.Region.dwUnCommittedSize;

            heapStats.regionsStats.push_back(std::move(reg));

            lastUsedRegion = heapStats.regionsStats.end();

            continue;
        }

        if (heapEntry.wFlags == PROCESS_HEAP_ENTRY_BUSY || heapEntry.wFlags == 0)
        {
            if (IsInRegion(heapStats, lastUsedRegion, heapEntry) == false)
                lastUsedRegion = GetRegion(heapStats, heapEntry);

            UpdateBlocksStats(
                lastUsedRegion != heapStats.regionsStats.end() ? lastUsedRegion->total : heapStats.bwrStats.total,
                heapEntry
            );
        }

        if (heapEntry.wFlags == PROCESS_HEAP_ENTRY_BUSY)
        {
            if (g_settings.bSearchStrings == true)
            {
                size_t blockSize = heapEntry.cbData;
                size_t currentPosition = 0;
                size_t overhead = heapEntry.cbOverhead;
                char* str = reinterpret_cast<char*>(heapEntry.lpData);

                if (str != nullptr)
                {
                    while (currentPosition < blockSize && str[currentPosition] != '\0' && isprint(str[currentPosition]) != 0)
                        currentPosition++;

                    if (currentPosition != 0 && str[currentPosition] == '\0')
                    {
                        WH_string s(str, currentPosition);
                        g_logger.LogInfo("Found string: [{}] ptr = {} strLength = {} blockSize = {} overhead = {}",
                            s, heapEntry.lpData, currentPosition, blockSize, overhead);
                    }
                }
            }

            UpdateBlocksStats(
                lastUsedRegion != heapStats.regionsStats.end() ? lastUsedRegion->used : heapStats.bwrStats.used,
                heapEntry
            );
            continue;
        }

        if (heapEntry.wFlags == 0)
        {
            UpdateBlocksStats(
                lastUsedRegion != heapStats.regionsStats.end() ? lastUsedRegion->free : heapStats.bwrStats.free,
                heapEntry
            );
            continue;
        }

        g_logger.LogError("Unsupported heap entry:\n{}", HeapEntryToString(heapEntry));
        bRes = false;
        break;
    }

    if (bRes == true)
    {
        DWORD err = GetLastError();
        if (err != ERROR_NO_MORE_ITEMS)
        {
            g_logger.LogError("HeapWalk failed: {}", err);
            bRes = false;
        }
    }

end:

    if (bIsLocked == false)
    {
        auto unlocked = HeapUnlock(hHeap);
        if (unlocked == FALSE)
        {
            g_logger.LogError("Failed to unlock heap: {}", GetLastError());
            bRes = false;
        }
    }

    if (bRes == true)
    {
        g_logger.LogInfo("GetHeapStatistics succeeded");

        if (generateAdditionalStats == true)
        {
            GenerateAdditionalHeapStats(heapStats);
        }
    }

    return bRes;
}

bool HeapAnalyzer::GetHeapsStatistics(std::initializer_list<HANDLE> ignoredHeaps, HeapsStats& heapsStats)
{
    static constexpr size_t kMaxNumOfRetries = 10;

    extern HANDLE g_hWorkingHeap;

    using HeapsVector = WH_vector<HANDLE>;

    auto isIgnoredHeap = [&](HANDLE h) { return std::find(ignoredHeaps.begin(), ignoredHeaps.end(), h) != ignoredHeaps.end(); };

    PHANDLE hHeaps = NULL;
    DWORD numOfHeaps;
    BOOL bWinRes;
    bool bRes = true;
    HeapsVector lockedHeaps;
    size_t retryNo;

    do {
        for (retryNo = 0; retryNo < kMaxNumOfRetries; retryNo++)
        {
            numOfHeaps = GetProcessHeaps(0, NULL);
            if (numOfHeaps == 0)
            {
                g_logger.LogError("number of heaps is 0: ", GetLastError());
                continue;
            }

            DWORD bufferSize = sizeof(*hHeaps) * numOfHeaps;

            hHeaps = reinterpret_cast<PHANDLE>(HeapAlloc(g_hWorkingHeap, 0, bufferSize));
            if (hHeaps == NULL)
            {
                g_logger.LogError("failed to allocate the buffer for heaps: {}", bufferSize);
                continue;
            }

            DWORD tmp = GetProcessHeaps(numOfHeaps, hHeaps);
            if (tmp == 0)
            {
                g_logger.LogError("failed to get heaps: ", GetLastError());
                HeapFree(g_hWorkingHeap, 0, hHeaps);
                hHeaps = NULL;
                continue;
            }

            if (tmp != numOfHeaps)
            {
                g_logger.LogError("found {} heaps, but expected {}", tmp, numOfHeaps);
                HeapFree(g_hWorkingHeap, 0, hHeaps);
                hHeaps = NULL;
                continue;
            }

            break;
        }

        if (retryNo == kMaxNumOfRetries)
        {
            g_logger.LogError("couldn't get process heaps!");
            bRes = false;
            break;
        }

        g_logger.LogInfo("found {} heaps", numOfHeaps);

        lockedHeaps.reserve(numOfHeaps);

        for (auto h : std::ranges::subrange(hHeaps, hHeaps + numOfHeaps))
        {
            if (isIgnoredHeap(h) == true)
            {
                g_logger.LogInfo("{} is ignored", h);
                continue;
            }

            if (IsLockableHeap(h) == false)
            {
                g_logger.LogInfo("{} is skipped because it is not lockable", h);
                continue;
            }

            if (HeapValidate(h, 0, NULL) == FALSE)
            {
                g_logger.LogInfo("{} is skipped because we cannot validate it: {}", h, GetLastError());
                continue;
            }

            bWinRes = HeapLock(h);
            if (bWinRes == FALSE)
            {
                g_logger.LogError("{} is ignored because HeapLock failed: {}", h, GetLastError());
                bRes = false; // return false if we couldn't analyze a heap
                continue;
            }

            lockedHeaps.push_back(h);

            g_logger.LogInfo("{} will be analyzed", h);
        }

        heapsStats.reserve(lockedHeaps.size());

        for (auto h : lockedHeaps)
        {
            HeapStats stats;

            if (GetHeapStatistics(h, true, stats, false) == false)
            {
                g_logger.LogError("failed to get statistics for heap: {}", h);
                bRes = false; // return false if we couldn't get statistics for a heap
            }
            else
            {
                g_logger.LogInfo("collected statistics for heap: {}", h);
                heapsStats.push_back(std::move(stats));
            }

            if (HeapUnlock(h) == FALSE)
                g_logger.LogError("failed to unlock heap {}: {}", h, GetLastError());
        }

        for (auto& h : heapsStats)
        {
            GenerateAdditionalHeapStats(h);
        }
    } while (false);

    if (hHeaps != NULL)
        HeapFree(g_hWorkingHeap, 0, hHeaps);

    return bRes;
}

WH_string HeapAnalyzer::HeapFlagsToString(WORD flags)
{
    WH_string res;
    auto addFlag = [&](WORD f, const char* str)
    {
        if ((flags & f) == 0)
            return;

        if (res.empty() == false)
            res += " | ";

        res += str;
    };

    addFlag(PROCESS_HEAP_REGION, "Region");
    addFlag(PROCESS_HEAP_UNCOMMITTED_RANGE, "UncommittedRange");
    addFlag(PROCESS_HEAP_ENTRY_BUSY, "Busy");
    addFlag(PROCESS_HEAP_SEG_ALLOC, "SegAlloc");
    addFlag(PROCESS_HEAP_ENTRY_MOVEABLE, "Moveable");
    addFlag(PROCESS_HEAP_ENTRY_DDESHARE, "DDEShare");

    return res;
}

WH_string HeapAnalyzer::HeapEntryToString(const PROCESS_HEAP_ENTRY& heapEntry)
{
    static constexpr char kSeparator[] = "\n";
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Address"), sizeof("Size"), sizeof("Overhead"),
        sizeof("RegIndex"), sizeof("Flags"), sizeof("hMem"),
        sizeof("CSize"), sizeof("USize"), sizeof("FBlock"), sizeof("LBlock"),
    }) - 1;

    WH_string result;

    result += NormalizeFieldName("Address", kMaxFieldName) + ToWHString(heapEntry.lpData) + kSeparator;
    result += NormalizeFieldName("Size", kMaxFieldName) + ToWHString(heapEntry.cbData) + kSeparator;
    result += NormalizeFieldName("Overhead", kMaxFieldName) + ToWHString(static_cast<unsigned int>(heapEntry.cbOverhead)) + kSeparator;
    result += NormalizeFieldName("RegIndex", kMaxFieldName) + ToWHString(static_cast<unsigned int>(heapEntry.iRegionIndex)) + kSeparator;
    result += NormalizeFieldName("Flags", kMaxFieldName) + HeapFlagsToString(heapEntry.wFlags) + kSeparator;

    if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && (heapEntry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0)
        result += NormalizeFieldName("hMem", kMaxFieldName) + ToWHString(heapEntry.Block.hMem) + kSeparator;

    if ((heapEntry.wFlags & PROCESS_HEAP_REGION) != 0)
    {
        result += NormalizeFieldName("CSize", kMaxFieldName) + ToWHString(heapEntry.Region.dwCommittedSize) + kSeparator;
        result += NormalizeFieldName("USize", kMaxFieldName) + ToWHString(heapEntry.Region.dwUnCommittedSize) + kSeparator;
        result += NormalizeFieldName("FBlock", kMaxFieldName) + ToWHString(heapEntry.Region.lpFirstBlock) + kSeparator;
        result += NormalizeFieldName("LBlock", kMaxFieldName) + ToWHString(heapEntry.Region.lpLastBlock) + kSeparator;
    }

    return result;
}

void HeapAnalyzer::UpdateBlocksStats(HeapStats::BlocksStats& blocksStats, const PROCESS_HEAP_ENTRY& heapEntry)
{
    size_t blockSizeWithOverhead = static_cast<size_t>(heapEntry.cbData) + heapEntry.cbOverhead;

    blocksStats.numberOfBlocks += 1;
    blocksStats.totalSize += heapEntry.cbData;
    blocksStats.totalOverhead += heapEntry.cbOverhead;

    blocksStats.minBlockSize = heapEntry.cbData;
    blocksStats.maxBlockSize = heapEntry.cbData;

    blocksStats.minBlockOverhead = heapEntry.cbOverhead;
    blocksStats.maxBlockOverhead = heapEntry.cbOverhead;

    blocksStats.minBlockSizeWithOverhead = blockSizeWithOverhead;
    blocksStats.maxBlockSizeWithOverhead = blockSizeWithOverhead;
}

void HeapAnalyzer::GenerateAdditionalHeapStats(HeapStats& heapStats)
{
    GenerateRegionsSummary(heapStats);
}

void HeapAnalyzer::GenerateRegionsSummary(HeapStats& heapStats)
{
    for (const auto& reg : heapStats.regionsStats)
    {
        heapStats.regionsSummary.numberOfRegions++;
        heapStats.regionsSummary.totalSize += reg.regionSize;
        heapStats.regionsSummary.totalOverhead += reg.regionOverhead;
        heapStats.regionsSummary.totalCommittedSize += reg.regionCommittedSize;
        heapStats.regionsSummary.totalUncommittedSize += reg.regionUncommittedSize;

        heapStats.regionsSummary.minRegionSize = reg.regionSize;
        heapStats.regionsSummary.maxRegionSize = reg.regionSize;

        heapStats.regionsSummary.minRegionOverhead = reg.regionOverhead;
        heapStats.regionsSummary.maxRegionOverhead = reg.regionOverhead;

        heapStats.regionsSummary.minRegionCommittedSize = reg.regionCommittedSize;
        heapStats.regionsSummary.maxRegionCommittedSize = reg.regionCommittedSize;

        heapStats.regionsSummary.minRegionUncommittedSize = reg.regionUncommittedSize;
        heapStats.regionsSummary.maxRegionUncommittedSize = reg.regionUncommittedSize;

        MergeBlocksStats(heapStats.regionsSummary.total, reg.total);
        MergeBlocksStats(heapStats.regionsSummary.used, reg.used);
        MergeBlocksStats(heapStats.regionsSummary.free, reg.free);
    }
}

void HeapAnalyzer::MergeBlocksStats(HeapStats::BlocksStats& dst, const HeapStats::BlocksStats& src)
{
    dst.numberOfBlocks += src.numberOfBlocks;
    dst.totalSize += src.totalSize;
    dst.totalOverhead += src.totalOverhead;

    dst.minBlockSize = src.minBlockSize;
    dst.maxBlockSize = src.maxBlockSize;

    dst.minBlockOverhead = src.minBlockOverhead;
    dst.maxBlockOverhead = src.maxBlockOverhead;

    dst.minBlockSizeWithOverhead = src.minBlockSizeWithOverhead;
    dst.maxBlockSizeWithOverhead = src.maxBlockSizeWithOverhead;
}

bool HeapAnalyzer::RegionExists(const HeapStats& heapStats, const PROCESS_HEAP_ENTRY& entry)
{
    return std::find_if(heapStats.regionsStats.begin(), heapStats.regionsStats.end(),
        [&](const HeapStats::RegionStats& reg) -> bool
        {
            return reg.regionStart == reinterpret_cast<size_t>(entry.Region.lpFirstBlock) ||
                reg.regionEnd == reinterpret_cast<size_t>(entry.Region.lpLastBlock);
        }) != heapStats.regionsStats.end();
}

bool HeapAnalyzer::IsInRegion(const HeapStats& heapStats, HeapStats::RegionsStats::iterator region, const PROCESS_HEAP_ENTRY& heapEntry)
{
    if (region == heapStats.regionsStats.end())
        return false;

    size_t address = reinterpret_cast<size_t>(heapEntry.lpData);
    if (address >= region->regionStart && address <= region->regionEnd)
        return true;

    return false;
}

HeapStats::RegionsStats::iterator HeapAnalyzer::GetRegion(HeapStats& heapStats, const PROCESS_HEAP_ENTRY& heapEntry)
{
    auto address = reinterpret_cast<size_t>(heapEntry.lpData);
    return std::find_if(heapStats.regionsStats.begin(), heapStats.regionsStats.end(),
        [&](const HeapStats::RegionStats& region) -> bool
        {
            return address >= region.regionStart && address <= region.regionEnd;
        });
}

bool HeapAnalyzer::IsLockableHeap(HANDLE hHeap)
{
    static constexpr size_t kHeapFlagsOffset = 28;

    DWORD flags = *(reinterpret_cast<uint32_t*>(hHeap) + kHeapFlagsOffset);
    return (flags & HEAP_NO_SERIALIZE) == 0;
}

} // namespace WinapiHeap
