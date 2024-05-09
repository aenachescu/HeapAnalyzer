#pragma once

#include "HeapStatistics.h"

#include <Windows.h>

class HeapAnalyzer
{
public:
    HeapAnalyzer() = default;
    ~HeapAnalyzer() = default;

    HeapStatisticsPtr AnalyzeHeap(HANDLE hHeap);
    HeapsStatistics AnalyzeHeaps(std::initializer_list<HANDLE> ignoredHeaps = {});

private:
    WH_string HeapFlagsToString(WORD flags);
    WH_string HeapEntryToString(const PROCESS_HEAP_ENTRY& heapEntry);

    bool AnalyzeHeapImpl(HANDLE hHeap, HeapStatistics& heapStats);
    PHANDLE GetHeaps(DWORD& numOfHeaps);

    bool IsLockableHeap(HANDLE hHeap);
};

