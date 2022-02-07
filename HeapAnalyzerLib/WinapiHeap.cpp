#include "pch.h"
#include "WinapiHeap.h"
#include "Logger.h"

#include <algorithm>
#include <ranges>

extern Logger g_logger;

namespace WinapiHeap
{

template<typename T>
concept MinMaxConcept = requires(T a)
{
    a.getValue();
    a.getCounter();
};

template<MinMaxConcept T>
std::string MinMaxToString(T& val, const char* text = "", size_t identation = 0, const char* counterText = " Count: ")
{
    std::string result(identation, ' ');
    result += text;
    result += std::to_string(val.getValue());
    result += counterText;
    result += std::to_string(val.getCounter());

    return result;
}

static std::string NormalizeFieldName(const char* fieldName, size_t maxFieldName)
{
    std::string result = fieldName;
    result.append(maxFieldName - result.size(), ' ');
    result += " : ";

    return result;
}

static std::string HeapInfoToStr(ULONG info)
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

    return std::to_string(info);
}

static std::string PointerToString(void* ptr)
{
    std::ostringstream ss;
    ss << ptr;
    return ss.str();
}

std::string HeapStats::BlocksStats::ToString(const char* blockName, size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Num"), sizeof("Size"), sizeof("Overhead"),
        sizeof("Shortest"), sizeof("Longest"), sizeof("ShortestOh"),
        sizeof("LongestOh"), sizeof("ShortestBnO"), sizeof("LongestBnO"),
    }) - 1;

    std::string result;
    std::string identationStr = std::string(identation, ' ');

    result += identationStr + "Blocks stats - " + blockName + separator;

    identation += 4;
    identationStr = std::string(identation, ' ');

    result += identationStr + NormalizeFieldName("Num", kMaxFieldName) + std::to_string(num) + separator;
    result += identationStr + NormalizeFieldName("Size", kMaxFieldName) + std::to_string(size) + separator;
    result += identationStr + NormalizeFieldName("Overhead", kMaxFieldName) + std::to_string(overhead) + separator;

    result += MinMaxToString(shortestBlock, NormalizeFieldName("Shortest", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestBlock, NormalizeFieldName("Longest", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestOverhead, NormalizeFieldName("ShortestOh", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestOverhead, NormalizeFieldName("LongestOh", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestBlockWithOverhead, NormalizeFieldName("ShortestBnO", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestBlockWithOverhead, NormalizeFieldName("LongestBnO", kMaxFieldName).c_str(), identation) + separator;

    return result;
}

std::string HeapStats::RegionStats::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Start"), sizeof("End"), sizeof("Size"),
        sizeof("Overhead"), sizeof("Committed"), sizeof("Uncommitted"),
    }) - 1;

    std::string result;
    std::string identationStr = std::string(identation, ' ');

    result += identationStr + NormalizeFieldName("Start", kMaxFieldName) +
        PointerToString(reinterpret_cast<void*>(regionStart)) + separator;
    result += identationStr + NormalizeFieldName("End", kMaxFieldName) +
        PointerToString(reinterpret_cast<void*>(regionEnd)) + separator;
    result += identationStr + NormalizeFieldName("Size", kMaxFieldName) + std::to_string(regionSize) + separator;
    result += identationStr + NormalizeFieldName("Overhead", kMaxFieldName) + std::to_string(regionOverhead) + separator;
    result += identationStr + NormalizeFieldName("Committed", kMaxFieldName) + std::to_string(regionCommittedSize) + separator;
    result += identationStr + NormalizeFieldName("Uncommitted", kMaxFieldName) + std::to_string(regionUncommittedSize) + separator;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

std::string HeapStats::RegionsStats::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("NumberOfRegions"), sizeof("Size"), sizeof("Overhead"), sizeof("Committed"), sizeof("Uncommitted"),
        sizeof("LongestSize"), sizeof("ShortestSize"), sizeof("LongestOverhead"), sizeof("ShortestOverhead"),
        sizeof("LongestCommitted"), sizeof("ShortestCommitted"), sizeof("LongestUncommitted"), sizeof("ShortestUncommitted"),
    }) - 1;

    std::string result;
    std::string identationStr = std::string(identation, ' ');

    result += identationStr + NormalizeFieldName("NumberOfRegions", kMaxFieldName) + std::to_string(numberOfRegions) + separator;
    result += identationStr + NormalizeFieldName("Size", kMaxFieldName) + std::to_string(size) + separator;
    result += identationStr + NormalizeFieldName("Overhead", kMaxFieldName) + std::to_string(overhead) + separator;
    result += identationStr + NormalizeFieldName("Committed", kMaxFieldName) + std::to_string(committedSize) + separator;
    result += identationStr + NormalizeFieldName("Uncommitted", kMaxFieldName) + std::to_string(uncommittedSize) + separator;

    result += MinMaxToString(longestSize, NormalizeFieldName("LongestSize", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestSize, NormalizeFieldName("ShortestSize", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestOverhead, NormalizeFieldName("LongestOverhead", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestOverhead, NormalizeFieldName("ShortestOverhead", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestCommittedSize, NormalizeFieldName("LongestCommitted", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestCommittedSize, NormalizeFieldName("ShortestCommitted", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestUncommittedSize, NormalizeFieldName("LongestUncommitted", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(shortestUncommittedSize, NormalizeFieldName("ShortestUncommitted", kMaxFieldName).c_str(), identation) + separator;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

std::string HeapStats::BlocksWithoutRegionStats::ToString(size_t identation, const char* separator) const
{
    std::string result;

    result += total.ToString("total", identation, separator);
    result += used.ToString("used", identation, separator);
    result += free.ToString("free", identation, separator);

    return result;
}

std::string HeapStats::UncommittedRangeStats::ToString(size_t identation, const char* separator) const
{
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Num"), sizeof("Size"), sizeof("Shortest"),
        sizeof("Longest"), sizeof("Overhead"), sizeof("RegIdx"),
    }) - 1;

    std::string result;
    std::string identationStr = std::string(identation, ' ');

    result += identationStr + NormalizeFieldName("Num", kMaxFieldName) + std::to_string(numOfRanges) + separator;
    result += identationStr + NormalizeFieldName("Size", kMaxFieldName) + std::to_string(totalSize) + separator;
    result += MinMaxToString(shortestRange, NormalizeFieldName("Shortest", kMaxFieldName).c_str(), identation) + separator;
    result += MinMaxToString(longestRange, NormalizeFieldName("Longest", kMaxFieldName).c_str(), identation) + separator;
    result += identationStr + NormalizeFieldName("Overhead", kMaxFieldName) + std::to_string(longestOverhead.getValue()) + separator;
    result += identationStr + NormalizeFieldName("RegIdx", kMaxFieldName) + std::to_string(biggestRegionIndex.getValue()) + separator;

    return result;
}

std::string HeapStats::ToString(bool includeRegions, const char* separator) const
{
    std::string result;
    bool bFirstRegion = true;

    result += "Heap: " + PointerToString(reinterpret_cast<void*>(heapAddress)) + separator;
    result += "Info: " + HeapInfoToStr(heapInfo) + separator;

    result += "Regions stats:";
    result += separator;
    result += regionsStats.ToString(4, separator);

    result += "Uncommitted range stats:";
    result += separator;
    result += uncommittedRangeStats.ToString(4, separator);

    result += "Blocks without regions:";
    result += separator;
    result += bwrStats.ToString(4, separator);

    if (includeRegions == true)
    {
        result += "Regions:";
        result += separator;
        for (const auto& r : regions)
        {
            if (bFirstRegion == true)
                bFirstRegion = false;
            else
                result += "    " + std::string(50, '-') + separator;

            result += r.ToString(4, separator);
        }
    }

    return result;
}

bool HeapAnalyzer::GetHeapStatistics(HANDLE hHeap, bool bIsLocked, HeapStats& heapStats)
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
    auto lastUsedRegion = heapStats.regions.end();

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
            heapStats.uncommittedRangeStats.numOfRanges += 1;
            heapStats.uncommittedRangeStats.totalSize += heapEntry.cbData;

            heapStats.uncommittedRangeStats.shortestRange = heapEntry.cbData;
            heapStats.uncommittedRangeStats.longestRange = heapEntry.cbData;

            heapStats.uncommittedRangeStats.longestOverhead = heapEntry.cbOverhead;
            heapStats.uncommittedRangeStats.biggestRegionIndex = heapEntry.iRegionIndex;

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

            heapStats.regions.push_back(std::move(reg));

            lastUsedRegion = heapStats.regions.end();

            continue;
        }

        if (heapEntry.wFlags == PROCESS_HEAP_ENTRY_BUSY || heapEntry.wFlags == 0)
        {
            if (IsInRegion(heapStats, lastUsedRegion, heapEntry) == false)
                lastUsedRegion = GetRegion(heapStats, heapEntry);

            UpdateBlocksStats(
                lastUsedRegion != heapStats.regions.end() ? lastUsedRegion->total : heapStats.bwrStats.total,
                heapEntry
            );
        }

        if (heapEntry.wFlags == PROCESS_HEAP_ENTRY_BUSY)
        {
            UpdateBlocksStats(
                lastUsedRegion != heapStats.regions.end() ? lastUsedRegion->used : heapStats.bwrStats.used,
                heapEntry
            );
            continue;
        }

        if (heapEntry.wFlags == 0)
        {
            UpdateBlocksStats(
                lastUsedRegion != heapStats.regions.end() ? lastUsedRegion->free : heapStats.bwrStats.free,
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

    if (bRes == true)
        GenerateRegionsStats(heapStats);

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
        g_logger.LogInfo("GetHeapStatistics succeeded");

    return bRes;
}

bool HeapAnalyzer::GetHeapsStatistics(std::initializer_list<HANDLE> ignoredHeaps, HeapsStats& heapsStats)
{
    static constexpr size_t kMaxNumOfRetries = 10;

    extern HANDLE g_hWorkingHeap;

    using HeapsVector = std::vector<HANDLE, WorkingHeapAllocator<HANDLE>>;

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
                g_logger.LogError("got {} heaps, but expected {}", tmp, numOfHeaps);
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

        g_logger.LogInfo("got {} heaps", numOfHeaps);

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

            if (GetHeapStatistics(h, true, stats) == false)
            {
                g_logger.LogError("failed to get statistics for heap: {}", h);
                bRes = false; // return false if we couldn't get statistics for a heap
            }
            else
            {
                g_logger.LogInfo("got statistics for heap: {}", h);
                heapsStats.push_back(std::move(stats));
            }

            if (HeapUnlock(h) == FALSE)
                g_logger.LogError("failed to unlock heap {}: {}", h, GetLastError());
        }
    } while (false);

    if (hHeaps != NULL)
        HeapFree(g_hWorkingHeap, 0, hHeaps);

    return bRes;
}

std::string HeapAnalyzer::HeapFlagsToString(WORD flags)
{
    std::string res;
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

std::string HeapAnalyzer::HeapEntryToString(const PROCESS_HEAP_ENTRY& heapEntry)
{
    static constexpr char kSeparator[] = "\n";
    static constexpr size_t kMaxFieldName = std::max({
        sizeof("Address"), sizeof("Size"), sizeof("Overhead"),
        sizeof("RegIndex"), sizeof("Flags"), sizeof("hMem"),
        sizeof("CSize"), sizeof("USize"), sizeof("FBlock"), sizeof("LBlock"),
    }) - 1;

    std::string result;

    result += NormalizeFieldName("Address", kMaxFieldName) + PointerToString(heapEntry.lpData) + kSeparator;
    result += NormalizeFieldName("Size", kMaxFieldName) + std::to_string(heapEntry.cbData) + kSeparator;
    result += NormalizeFieldName("Overhead", kMaxFieldName) + std::to_string(static_cast<unsigned int>(heapEntry.cbOverhead)) + kSeparator;
    result += NormalizeFieldName("RegIndex", kMaxFieldName) + std::to_string(static_cast<unsigned int>(heapEntry.iRegionIndex)) + kSeparator;
    result += NormalizeFieldName("Flags", kMaxFieldName) + HeapFlagsToString(heapEntry.wFlags) + kSeparator;

    if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && (heapEntry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0)
        result += NormalizeFieldName("hMem", kMaxFieldName) + PointerToString(heapEntry.Block.hMem) + kSeparator;

    if ((heapEntry.wFlags & PROCESS_HEAP_REGION) != 0)
    {
        result += NormalizeFieldName("CSize", kMaxFieldName) + std::to_string(heapEntry.Region.dwCommittedSize) + kSeparator;
        result += NormalizeFieldName("USize", kMaxFieldName) + std::to_string(heapEntry.Region.dwUnCommittedSize) + kSeparator;
        result += NormalizeFieldName("FBlock", kMaxFieldName) + PointerToString(heapEntry.Region.lpFirstBlock) + kSeparator;
        result += NormalizeFieldName("LBlock", kMaxFieldName) + PointerToString(heapEntry.Region.lpLastBlock) + kSeparator;
    }

    return result;
}

void HeapAnalyzer::UpdateBlocksStats(HeapStats::BlocksStats& blocksStats, const PROCESS_HEAP_ENTRY& heapEntry)
{
    size_t blockSizeWithOverhead = static_cast<size_t>(heapEntry.cbData) + heapEntry.cbOverhead;

    blocksStats.num += 1;
    blocksStats.size += heapEntry.cbData;
    blocksStats.overhead += heapEntry.cbOverhead;

    blocksStats.shortestBlock = heapEntry.cbData;
    blocksStats.longestBlock = heapEntry.cbData;

    blocksStats.shortestOverhead = heapEntry.cbOverhead;
    blocksStats.longestOverhead = heapEntry.cbOverhead;

    blocksStats.shortestBlockWithOverhead = blockSizeWithOverhead;
    blocksStats.longestBlockWithOverhead = blockSizeWithOverhead;
}

void HeapAnalyzer::GenerateRegionsStats(HeapStats& heapStats)
{
    for (const auto& reg : heapStats.regions)
    {
        heapStats.regionsStats.numberOfRegions++;
        heapStats.regionsStats.size += reg.regionSize;
        heapStats.regionsStats.overhead += reg.regionOverhead;
        heapStats.regionsStats.committedSize += reg.regionCommittedSize;
        heapStats.regionsStats.uncommittedSize += reg.regionUncommittedSize;

        heapStats.regionsStats.longestSize = reg.regionSize;
        heapStats.regionsStats.shortestSize = reg.regionSize;

        heapStats.regionsStats.longestOverhead = reg.regionOverhead;
        heapStats.regionsStats.shortestOverhead = reg.regionOverhead;

        heapStats.regionsStats.longestCommittedSize = reg.regionCommittedSize;
        heapStats.regionsStats.shortestCommittedSize = reg.regionCommittedSize;

        heapStats.regionsStats.longestUncommittedSize = reg.regionUncommittedSize;
        heapStats.regionsStats.shortestUncommittedSize = reg.regionUncommittedSize;

        MergeBlocksStats(heapStats.regionsStats.total, reg.total);
        MergeBlocksStats(heapStats.regionsStats.used, reg.used);
        MergeBlocksStats(heapStats.regionsStats.free, reg.free);
    }
}

void HeapAnalyzer::MergeBlocksStats(HeapStats::BlocksStats& dst, const HeapStats::BlocksStats& src)
{
    dst.num += src.num;
    dst.size += src.size;
    dst.overhead += src.overhead;

    dst.shortestBlock = src.shortestBlock;
    dst.longestBlock = src.longestBlock;

    dst.shortestOverhead = src.shortestOverhead;
    dst.longestOverhead = src.longestOverhead;

    dst.shortestBlockWithOverhead = src.shortestBlockWithOverhead;
    dst.longestBlockWithOverhead = src.longestBlockWithOverhead;
}

bool HeapAnalyzer::RegionExists(const HeapStats& heapStats, const PROCESS_HEAP_ENTRY& entry)
{
    return std::find_if(heapStats.regions.begin(), heapStats.regions.end(),
        [&](const HeapStats::RegionStats& reg) -> bool
        {
            return reg.regionStart == reinterpret_cast<size_t>(entry.Region.lpFirstBlock) ||
                reg.regionEnd == reinterpret_cast<size_t>(entry.Region.lpLastBlock);
        }) != heapStats.regions.end();
}

bool HeapAnalyzer::IsInRegion(const HeapStats& heapStats, HeapStats::Regions::iterator region, const PROCESS_HEAP_ENTRY& heapEntry)
{
    if (region == heapStats.regions.end())
        return false;

    size_t address = reinterpret_cast<size_t>(heapEntry.lpData);
    if (address >= region->regionStart && address <= region->regionEnd)
        return true;

    return false;
}

HeapStats::Regions::iterator HeapAnalyzer::GetRegion(HeapStats& heapStats, const PROCESS_HEAP_ENTRY& heapEntry)
{
    auto address = reinterpret_cast<size_t>(heapEntry.lpData);
    return std::find_if(heapStats.regions.begin(), heapStats.regions.end(),
        [&](const HeapStats::RegionStats& region) -> bool
        {
            return address >= region.regionStart && address <= region.regionEnd;
        });
}

bool HeapAnalyzer::IsLockableHeap(HANDLE hHeap)
{
    DWORD flags = *(reinterpret_cast<uint32_t*>(hHeap) + 28);
    return (flags & HEAP_NO_SERIALIZE) == 0;
}

} // namespace WinapiHeap
