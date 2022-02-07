#pragma once

#include "Logger.h"
#include "Settings.h"

#include <exception>
#include <limits>

#include <Windows.h>

#undef max
#undef min

template <class T>
struct WorkingHeapAllocator
{
    static constexpr bool bEnableReport = false;

    typedef T value_type;

    WorkingHeapAllocator() = default;

    template <class U>
    constexpr WorkingHeapAllocator(const WorkingHeapAllocator<U>&) noexcept
    {
    }

    [[nodiscard]] T* allocate(std::size_t n)
    {
        extern HANDLE g_hWorkingHeap;

        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_array_new_length();

        if (auto p = reinterpret_cast<T*>(HeapAlloc(g_hWorkingHeap, 0, n * sizeof(T))))
        {
            report(p, n);
            return p;
        }

        throw std::bad_alloc();
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        extern HANDLE g_hWorkingHeap;

        report(p, n, false);
        HeapFree(g_hWorkingHeap, 0, p);
    }

private:
    void report(T* p, std::size_t n, bool alloc = true) const
    {
        extern Settings g_settings;
        if (g_settings.bWorkingHeapAllocatorLogging == true)
        {
            extern Logger g_logger;
            g_logger.LogInfo("{} {} ({} * {}) bytes at {}",
                alloc ? "allocate" : "deallocate",
                sizeof(T) * n, sizeof(T), n, reinterpret_cast<void*>(p));
        }
    }
};
