#pragma once

#include "FieldStatistics.h"
#include "Allocator.h"
#include "StringUtils.h"
#include "Settings.h"

#include <Windows.h>

#include <format>
#include <algorithm>

class BlocksStatistics
{
public:
    static constexpr size_t kFieldNameAlignment = std::max({
        sizeof("NumberOfBlocks"),
        sizeof("Size"),
        sizeof("Overhead"),
        sizeof("SizeWithOverhead"),
    }) - 1 + FieldStatistics::kFieldNameAlignment;

    enum class Type
    {
        Total = 0,
        Used,
        Free,
    };

public:
    BlocksStatistics(Type t) : type(t)
    {
    }

    ~BlocksStatistics() = default;

    BlocksStatistics(const BlocksStatistics& other) = delete;
    BlocksStatistics(BlocksStatistics&& other) = delete;

    BlocksStatistics& operator=(const BlocksStatistics& other) = delete;
    BlocksStatistics& operator=(BlocksStatistics&& other) = delete;

    inline BlocksStatistics& operator+=(const BlocksStatistics& other)
    {
        if (type != other.type)
        {
            return *this;
        }

        numberOfBlocks += other.numberOfBlocks;
        size += other.size;
        overhead += other.overhead;
        sizeWithOverhead += other.sizeWithOverhead;

        return *this;
    }

    inline BlocksStatistics& operator+=(const PROCESS_HEAP_ENTRY& block)
    {
        numberOfBlocks++;
        size += static_cast<size_t>(block.cbData);
        overhead += static_cast<size_t>(block.cbOverhead);
        sizeWithOverhead += (static_cast<size_t>(block.cbData) + static_cast<size_t>(block.cbOverhead));

        return *this;
    }

    inline void Process()
    {
        size.Process(numberOfBlocks);
        overhead.Process(numberOfBlocks);
        sizeWithOverhead.Process(numberOfBlocks);
    }

    WH_string ToString(size_t identation, const char* separator) const
    {
        WH_string res;

        std::format_to(std
            ::back_inserter(res),
            "{:{}}{} blocks statistics{}",
            ' ', identation,
            TypeToString(),
            separator);

        identation += Settings::kIdentationSize;

        std::format_to(
            std::back_inserter(res),
            "{:{}}{:{}} : {}{}",
            ' ', identation,
            "NumberOfBlocks", kFieldNameAlignment,
            numberOfBlocks,
            separator);

        res += size.ToString(identation, separator, "Size", kFieldNameAlignment) + separator;
        res += overhead.ToString(identation, separator, "Overhead", kFieldNameAlignment) + separator;
        res += sizeWithOverhead.ToString(identation, separator, "SizeWithOverhead", kFieldNameAlignment);

        return res;
    }

    inline size_t GetNumberOfBlocks() const
    {
        return numberOfBlocks;
    }

    inline const FieldStatistics& GetSize() const
    {
        return size;
    }

    inline const FieldStatistics& GetOverhead() const
    {
        return overhead;
    }

    inline const FieldStatistics& GetSizeWithOverhead() const
    {
        return sizeWithOverhead;
    }

private:
    const char* TypeToString() const
    {
        switch (type)
        {
        case Type::Total:
            return "Total";
        case Type::Used:
            return "Used";
        case Type::Free:
            return "Free";
        default:
            break;
        }

        return "Unknown";
    }

private:
    const Type type;

    size_t numberOfBlocks = 0;

    FieldStatistics size;
    FieldStatistics overhead;
    FieldStatistics sizeWithOverhead;
};
