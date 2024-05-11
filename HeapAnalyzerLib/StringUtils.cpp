#include "pch.h"
#include "StringUtils.h"

static WH_string HeapFlagsToString(WORD flags)
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

    if (res.empty() == true)
    {
        res = "Free";
    }

    return res;
}

WH_string ToString(const PROCESS_HEAP_ENTRY& heapEntry)
{
    WH_string res;
    std::format_to(
        std::back_inserter(res),
        "Address = {:#018x}, Size = {:<7}, Overhead = {:<3}, RegionIndex = {:<3}, Flags = {}",
        reinterpret_cast<std::uintptr_t>(heapEntry.lpData),
        heapEntry.cbData,
        heapEntry.cbOverhead,
        heapEntry.iRegionIndex,
        HeapFlagsToString(heapEntry.wFlags));

    if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && (heapEntry.wFlags & PROCESS_HEAP_ENTRY_MOVEABLE) != 0)
    {
        std::format_to(
            std::back_inserter(res),
            ", hMem = {:#018x}",
            reinterpret_cast<std::uintptr_t>(heapEntry.Block.hMem));
    }

    if ((heapEntry.wFlags & PROCESS_HEAP_REGION) != 0)
    {
        std::format_to(
            std::back_inserter(res),
            ", CommittedSize = {:<7}, UncommittedSize = {:<7}, FirstBlock = {:#018x}, LastBlock = {:#018x}",
            heapEntry.Region.dwCommittedSize,
            heapEntry.Region.dwUnCommittedSize,
            reinterpret_cast<std::uintptr_t>(heapEntry.Region.lpFirstBlock),
            reinterpret_cast<std::uintptr_t>(heapEntry.Region.lpLastBlock));
    }

    return res;
}
