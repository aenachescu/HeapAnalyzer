#pragma once

#include "FieldStatistics.h"
#include "Allocator.h"

#include <Windows.h>

class BlocksStatistics
{
public:
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

    WH_string ToString(size_t identation, const char* separator) const;

private:
    Type type;

    size_t numberOfBlocks = 0;

    FieldStatistics size;
    FieldStatistics overhead;
    FieldStatistics sizeWithOverhead;
};
