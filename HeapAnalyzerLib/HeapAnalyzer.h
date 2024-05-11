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
    bool AnalyzeHeapImpl(HANDLE hHeap, HeapStatistics& heapStats);
    PHANDLE GetHeaps(DWORD& numOfHeaps);

    bool IsLockableHeap(HANDLE hHeap);
};

