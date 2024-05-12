#include "pch.h"
#include "RegionsSummary.h"

#include <format>

WH_string RegionsSummary::ToString(size_t identation, const char* separator) const
{
    WH_string res;

    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "NumberOfRegions", kFieldNameAlignment,
        numberOfRegions,
        separator);

    res += size.ToString(identation, separator, "Size", kFieldNameAlignment) + separator;
    res += overhead.ToString(identation, separator, "Overhead", kFieldNameAlignment) + separator;
    res += sizeWithOverhead.ToString(identation, separator, "SizeWithOverhead", kFieldNameAlignment) + separator;

    res += committedMemory.ToString(identation, separator, "CommittedMemory", kFieldNameAlignment) + separator;
    res += uncommittedMemory.ToString(identation, separator, "UncommittedMemory", kFieldNameAlignment) + separator;
    res += totalMemory.ToString(identation, separator, "TotalMemory", kFieldNameAlignment) + separator;

    res += total.ToString(identation, separator) + separator;
    res += used.ToString(identation, separator) + separator;
    res += free.ToString(identation, separator);

    return res;
}
