#pragma once

struct Settings
{
    static constexpr char kSharedMemoryName[] = "HeapAnalyzerSettings";
    static constexpr size_t kIdentationSize = 4;

    bool bStatsPerRegionLogging = false;
    bool bHeapEntryLogging = false;
    bool bSearchStrings = false;
};
