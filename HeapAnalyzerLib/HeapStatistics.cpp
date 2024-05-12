#include "pch.h"

#include "HeapStatistics.h"
#include "Logger.h"
#include "StringUtils.h"
#include "Settings.h"

#include <algorithm>

extern Logger g_logger;

static WH_string HeapInfoToString(ULONG info)
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

    return ToString(info);
}

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

WH_string HeapStatistics::ToString(bool includeRegions) const
{
    WH_string res;
    size_t nextIdent = Settings::kIdentationSize;
    const char* separator = "\n";

    std::format_to(
        std::back_inserter(res),
        "Heap: {:#018x}\nInfo: {}\nRegions summary:\n{}\n",
        reinterpret_cast<std::uintptr_t>(heapAddress),
        HeapInfoToString(heapInfo),
        regionsSummary.ToString(nextIdent, separator));

    if (standaloneBlocks.GetTotalBlocksStatistics().GetNumberOfBlocks() == 0)
    {
        res += "Standalone blocks statistics: none\n";
    }
    else
    {
        res += "Standalone blocks statistics:\n";
        res += standaloneBlocks.ToString(nextIdent, separator) + separator;
    }

    if (uncommittedRanges.GetNumberOfRanges() == 0)
    {
        res += "Uncommitted ranges statistics: none\n";
    }
    else
    {
        res += "Uncommitted ranges statistics:\n";
        res += uncommittedRanges.ToString(nextIdent, separator) + separator;
    }

    if (includeRegions == true)
    {
        if (regions.size() == 0)
        {
            res += "Regions: none\n";
        }
        else
        {
            bool bFirstRegion = true;
            WH_string regionSeparator = separator;
            regionSeparator.append(nextIdent, ' ');
            regionSeparator.append(Settings::kRegionSeparatorLength, '-');
            regionSeparator.append(separator);

            res += "Regions:\n";
            for (const auto& r : regions)
            {
                if (bFirstRegion == false)
                {
                    res += regionSeparator;
                }
                else
                {
                    bFirstRegion = false;
                }

                res += r->ToString(nextIdent, separator);
            }
        }
    }

    if (res.back() == '\n')
    {
        res.pop_back();
    }

    return res;
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
