#pragma once

struct Settings
{
    static constexpr char kSharedMemoryName[] = "HeapAnalyzerSettings";

    bool bStatsPerRegionLogging = false;
    bool bHeapEntryLogging = false;
    bool bSearchStrings = false;
};
