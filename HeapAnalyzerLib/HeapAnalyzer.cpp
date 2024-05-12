#include "pch.h"
#include "HeapAnalyzer.h"
#include "Logger.h"
#include "StringUtils.h"
#include "Settings.h"

#include <algorithm>
#include <ranges>

extern Settings g_settings;
extern Logger g_logger;
extern HANDLE g_hWorkingHeap;

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

    heapStats->Process();

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
            g_logger.LogInfo("Processing heap entry: {}", ToString(heapEntry));
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

bool HeapAnalyzer::IsLockableHeap(HANDLE hHeap)
{
    static constexpr size_t kHeapFlagsOffset = 28;

    DWORD flags = *(reinterpret_cast<uint32_t*>(hHeap) + kHeapFlagsOffset);
    return (flags & HEAP_NO_SERIALIZE) == 0;
}
