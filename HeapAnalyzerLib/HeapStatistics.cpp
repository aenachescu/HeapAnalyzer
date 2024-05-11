#include "pch.h"

#include "HeapStatistics.h"
#include "Logger.h"
#include "StringUtils.h"

#include <algorithm>

extern Logger g_logger;

bool HeapStatistics::HandleHeapEntry(const PROCESS_HEAP_ENTRY& entry)
{
    if (entry.wFlags == PROCESS_HEAP_REGION)
    {
        if (RegionExists(entry.Region.lpFirstBlock, entry.Region.lpLastBlock) == true)
        {
            g_logger.LogError("Region already exists: {}", ::ToString(entry));
            return false;
        }

        regions.emplace_back(MakeWHUnique<RegionStatistics>(entry));
        lastUsedRegion = regions.end(); // invalidate iterator

        return true;
    }

    if (entry.wFlags == PROCESS_HEAP_UNCOMMITTED_RANGE)
    {
        uncommittedRanges += entry;
        return true;
    }

    if (entry.wFlags == PROCESS_HEAP_ENTRY_BUSY || entry.wFlags == 0)
    {
        if (IsInRegion(lastUsedRegion, entry.lpData) == false)
        {
            lastUsedRegion = GetRegion(entry.lpData);
        }

        if (lastUsedRegion == regions.end())
        {
            standaloneBlocks += entry;
        }
        else
        {
            **lastUsedRegion += entry;
        }

        return true;
    }

    g_logger.LogError("Unsupported heap entry: {}", ::ToString(entry));

    return false;
}

WH_string HeapStatistics::ToString() const
{
    return WH_string("here should be heap stats");
}

bool HeapStatistics::RegionExists(void* start, void* end) const
{
    auto it = std::find_if(regions.begin(), regions.end(),
        [start, end](const RegionStatisticsPtr& region) -> bool
        {
            return region->GetStart() == start || region->GetEnd() == end;
        });
    return it != regions.end();
}

bool HeapStatistics::IsInRegion(RegionIterator region, void* addr) const
{
    if (region == regions.end())
        return false;

    return addr >= (*region)->GetStart() && addr <= (*region)->GetEnd();
}

HeapStatistics::RegionIterator HeapStatistics::GetRegion(void* addr)
{
    return std::find_if(regions.begin(), regions.end(),
        [addr](const RegionStatisticsPtr& region) -> bool
        {
            return addr >= region->GetStart() && addr <= region->GetEnd();
        });
}
