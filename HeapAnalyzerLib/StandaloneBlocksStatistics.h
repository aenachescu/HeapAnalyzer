#pragma once

#include "BlocksStatistics.h"
#include "Allocator.h"

#include <Windows.h>

class StandaloneBlocksStatistics
{
public:
    StandaloneBlocksStatistics() = default;
    ~StandaloneBlocksStatistics() = default;

    StandaloneBlocksStatistics(const StandaloneBlocksStatistics& other) = delete;
    StandaloneBlocksStatistics(StandaloneBlocksStatistics&& other) = delete;

    StandaloneBlocksStatistics& operator=(const StandaloneBlocksStatistics& other) = delete;
    StandaloneBlocksStatistics& operator=(StandaloneBlocksStatistics&& other) = delete;

    inline StandaloneBlocksStatistics& operator+=(const PROCESS_HEAP_ENTRY& block)
    {
        if ((block.wFlags & PROCESS_HEAP_ENTRY_BUSY) == PROCESS_HEAP_ENTRY_BUSY)
        {
            used += block;
        }
        else
        {
            free += block;
        }

        total += block;

        return *this;
    }

    inline void Process()
    {
        total.Process();
        used.Process();
        free.Process();
    }

    WH_string ToString(size_t identation, const char* separator) const;

private:
    BlocksStatistics total{ BlocksStatistics::Type::Total };
    BlocksStatistics used{ BlocksStatistics::Type::Used };
    BlocksStatistics free{ BlocksStatistics::Type::Free };
};
