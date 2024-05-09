#include "pch.h"
#include "WinapiHeap.h"
#include "Logger.h"
#include "StringUtils.h"
#include "Settings.h"

#include <algorithm>
#include <ranges>

extern Settings g_settings;
extern Logger g_logger;
extern HANDLE g_hWorkingHeap;

/*
bool HeapAnalyzer::GetHeapStatistics(HANDLE hHeap, bool bIsLocked, HeapStats& heapStats, bool generateAdditionalStats)
{
    static constexpr size_t kDefaultRegionsCapacity = 128;

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
    PROCESS_HEAP_ENTRY heapEntry = { 0 };
    auto lastUsedRegion = heapStats.regionsStats.end();

    heapStats.heapAddress = hHeap;
    heapStats.regionsStats.reserve(kDefaultRegionsCapacity);

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

            heapStats.regionsStats.emplace_back();
            lastUsedRegion = heapStats.regionsStats.end(); // invalidate iterator

            RegionStats& reg = heapStats.regionsStats.back();

            reg.regionStart = reinterpret_cast<size_t>(heapEntry.lpData);
            reg.regionEnd = reinterpret_cast<size_t>(heapEntry.Region.lpLastBlock);
            reg.regionSize = heapEntry.cbData;
            reg.regionOverhead = heapEntry.cbOverhead;
            reg.regionCommittedSize = heapEntry.Region.dwCommittedSize;
            reg.regionUncommittedSize = heapEntry.Region.dwUnCommittedSize;

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
*/

HeapStatisticsPtr HeapAnalyzer::AnalyzeHeap(HANDLE hHeap)
{
    g_logger.LogInfo("analyzing heap {}", hHeap);

    BOOL bRes = FALSE;
    ULONG heapInfo = 0;
    HeapStatisticsPtr heapStats;

    if (IsLockableHeap(hHeap) == false)
    {
        g_logger.LogError("heap {} is not lockable", hHeap);
        return nullptr;
    }

    if (HeapValidate(hHeap, 0, NULL) == FALSE)
    {
        g_logger.LogInfo("failed to validate heap {}: {}", hHeap, GetLastError());
        return nullptr;
    }

    bRes = HeapLock(hHeap);
    if (bRes == FALSE)
    {
        g_logger.LogError("failed to lock heap {}: {}", hHeap, GetLastError());
        return nullptr;
    }

    do {
        bRes = HeapQueryInformation(hHeap, HeapCompatibilityInformation, &heapInfo, sizeof(heapInfo), NULL);
        if (bRes == FALSE)
        {
            g_logger.LogError("failed to get heap info: {}", GetLastError());
            break;
        }

        heapStats = MakeWHUnique<HeapStatistics>(hHeap, heapInfo);
        if (heapStats == nullptr)
        {
            g_logger.LogError("failed to allocate heap info: {}", GetLastError());
            break;
        }

        if (AnalyzeHeapImpl(hHeap, *heapStats) == false)
        {
            g_logger.LogError("failed to analyze heap {}", hHeap);
            heapStats.reset();
        }

        g_logger.LogInfo("heap {} has been analyzed successfully", hHeap);
    } while (false);

    if (HeapUnlock(hHeap) == FALSE)
    {
        g_logger.LogError("failed to unlock heap {}: {}", hHeap, GetLastError());
    }

    return heapStats;
}

HeapsStatistics HeapAnalyzer::AnalyzeHeaps(std::initializer_list<HANDLE> ignoredHeaps)
{
    auto isIgnoredHeap = [&](HANDLE h) { return std::find(ignoredHeaps.begin(), ignoredHeaps.end(), h) != ignoredHeaps.end(); };

    PHANDLE hHeaps = NULL;
    DWORD numOfHeaps = 0;
    ULONG heapInfo = 0;
    BOOL bWinRes = FALSE;
    WH_vector<HANDLE> lockedHeaps;
    HeapsStatistics heapsStats;

    do {
        hHeaps = GetHeaps(numOfHeaps);
        if (hHeaps == nullptr)
        {
            g_logger.LogError("failed to get process heaps");
            break;
        }

        lockedHeaps.reserve(numOfHeaps);

        for (auto h : std::ranges::subrange(hHeaps, hHeaps + numOfHeaps))
        {
            if (isIgnoredHeap(h) == true)
            {
                g_logger.LogInfo("heap {} is ignored", h);
                continue;
            }

            if (IsLockableHeap(h) == false)
            {
                g_logger.LogInfo("heap {} is skipped because it is not lockable", h);
                continue;
            }

            if (HeapValidate(h, 0, NULL) == FALSE)
            {
                g_logger.LogInfo("heap {} is skipped because it cannot be validated: {}", h, GetLastError());
                continue;
            }

            bWinRes = HeapLock(h);
            if (bWinRes == FALSE)
            {
                g_logger.LogError("heap {} is ignored because HeapLock failed: {}", h, GetLastError());
                continue;
            }

            lockedHeaps.push_back(h);

            g_logger.LogInfo("heap {} will be analyzed", h);
        }

        heapsStats.reserve(lockedHeaps.size());

        for (auto h : lockedHeaps)
        {
            bWinRes = HeapQueryInformation(h, HeapCompatibilityInformation, &heapInfo, sizeof(heapInfo), NULL);
            if (bWinRes == FALSE)
            {
                g_logger.LogError("Failed to get heap info: {}", GetLastError());
            }
            else
            {
                heapsStats.emplace_back(MakeWHUnique<HeapStatistics>(h, heapInfo));
                if (AnalyzeHeapImpl(h, *heapsStats.back()) == false)
                {
                    g_logger.LogError("failed to analyze heap {}", h);
                    heapsStats.pop_back();
                }
                else
                {
                    g_logger.LogInfo("heap {} has been analyzed successfully", h);
                }
            }

            if (HeapUnlock(h) == FALSE)
            {
                g_logger.LogError("failed to unlock heap {}: {}", h, GetLastError());
            }
        }

        for (auto& h : heapsStats)
        {
            h->Process();
        }
    } while (false);

    if (hHeaps != nullptr)
    {
        HeapFree(g_hWorkingHeap, 0, hHeaps);
    }

    return heapsStats;
}

bool HeapAnalyzer::AnalyzeHeapImpl(HANDLE hHeap, HeapStatistics& heapStats)
{
    PROCESS_HEAP_ENTRY heapEntry = { 0 };
    DWORD err = ERROR_SUCCESS;

    while (HeapWalk(hHeap, &heapEntry) != FALSE)
    {
        if (g_settings.bHeapEntryLogging == true)
        {
            g_logger.LogInfo("Processing heap entry:\n{}", HeapEntryToString(heapEntry));
        }

        if (g_settings.bSearchStrings == true && heapEntry.wFlags == PROCESS_HEAP_ENTRY_BUSY)
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

        if (heapStats.HandleHeapEntry(heapEntry) == false)
        {
            return false;
        }
    }

    err = GetLastError();
    if (err != ERROR_NO_MORE_ITEMS)
    {
        g_logger.LogError("HeapWalk failed: {}", err);
        return false;
    }

    return true;
}

PHANDLE HeapAnalyzer::GetHeaps(DWORD& numOfHeaps)
{
    static constexpr size_t kMaxNumOfRetries = 10;

    numOfHeaps = 0;

    PHANDLE hHeaps = NULL;
    DWORD num = 0;

    for (size_t retryNo = 0; retryNo < kMaxNumOfRetries; retryNo++)
    {
        num = GetProcessHeaps(0, NULL);
        if (num == 0)
        {
            g_logger.LogError("number of heaps is 0: ", GetLastError());
            continue;
        }

        DWORD bufferSize = sizeof(*hHeaps) * num;

        hHeaps = reinterpret_cast<PHANDLE>(HeapAlloc(g_hWorkingHeap, 0, bufferSize));
        if (hHeaps == NULL)
        {
            g_logger.LogError("failed to allocate the buffer for heaps: {}", bufferSize);
            continue;
        }

        DWORD tmp = GetProcessHeaps(num, hHeaps);
        if (tmp == 0)
        {
            g_logger.LogError("failed to get heaps: ", GetLastError());
            HeapFree(g_hWorkingHeap, 0, hHeaps);
            hHeaps = NULL;
            continue;
        }

        if (tmp != num)
        {
            g_logger.LogError("found {} heaps, but expected {}", tmp, num);
            HeapFree(g_hWorkingHeap, 0, hHeaps);
            hHeaps = NULL;
            continue;
        }

        g_logger.LogInfo("found {} heaps", num);

        numOfHeaps = num;
        return hHeaps;
    }

    return nullptr;
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

bool HeapAnalyzer::IsLockableHeap(HANDLE hHeap)
{
    static constexpr size_t kHeapFlagsOffset = 28;

    DWORD flags = *(reinterpret_cast<uint32_t*>(hHeap) + kHeapFlagsOffset);
    return (flags & HEAP_NO_SERIALIZE) == 0;
}
