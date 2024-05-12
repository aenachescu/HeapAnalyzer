#include "pch.h"
#include "UncommittedRangesStatistics.h"

#include <format>

WH_string UncommittedRangesStatistics::ToString(size_t identation, const char* separator) const
{
    WH_string res;

    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "NumberOfRanges", kFieldNameAlignment,
        numberOfRanges,
        separator);

    res += size.ToString(identation, separator, "Size", kFieldNameAlignment) + separator;
    res += overhead.ToString(identation, separator, "Overhead", kFieldNameAlignment) + separator;
    res += sizeWithOverhead.ToString(identation, separator, "SizeWithOverhead", kFieldNameAlignment);

    return res;
}
