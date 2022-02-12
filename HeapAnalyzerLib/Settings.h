#pragma once

struct Settings
{
    static constexpr char kSharedMemoryName[] = "HeapAnalyzerSettings";

    bool bWorkingHeapAllocatorLogging = false;
    bool bStatsPerRegionLogging = false;
    bool bHeapEntryLogging = false;
    bool bSearchStrings = false;
};
