#include "pch.h"
#include "RegionStatistics.h"

#include <format>

WH_string RegionStatistics::ToString(size_t identation, const char* separator) const
{
    WH_string res;

    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {:#018x}{}",
        ' ', identation,
        "Start", kFieldNameAlignment,
        reinterpret_cast<std::uintptr_t>(start),
        separator);
    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {:#018x}{}",
        ' ', identation,
        "End", kFieldNameAlignment,
        reinterpret_cast<std::uintptr_t>(end),
        separator);

    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "Size", kFieldNameAlignment,
        ::ToString(size, true),
        separator);
    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "Overhead", kFieldNameAlignment,
        ::ToString(overhead, true),
        separator);
    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "SizeWithOverhead", kFieldNameAlignment,
        ::ToString(sizeWithOverhead, true),
        separator);

    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "CommittedMemory", kFieldNameAlignment,
        ::ToString(committedMemory, true),
        separator);
    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "UncommittedMemory", kFieldNameAlignment,
        ::ToString(uncommittedMemory, true),
        separator);
    std::format_to(
        std::back_inserter(res),
        "{:{}}{:{}} : {}{}",
        ' ', identation,
        "TotalMemory", kFieldNameAlignment,
        ::ToString(totalMemory, true),
        separator);

    res += total.ToString(identation, separator) + separator;
    res += used.ToString(identation, separator) + separator;
    res += free.ToString(identation, separator);

    return res;
}
