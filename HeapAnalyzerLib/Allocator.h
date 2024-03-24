#pragma once

#include <exception>
#include <limits>
#include <string>
#include <vector>
#include <sstream>

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
            return p;
        }

        throw std::bad_alloc();
    }

    void deallocate(T* p, [[maybe_unused]] std::size_t n) noexcept
    {
        extern HANDLE g_hWorkingHeap;

        HeapFree(g_hWorkingHeap, 0, p);
    }
};

using WH_string = std::basic_string<char, std::char_traits<char>, WorkingHeapAllocator<char>>;
using WH_ostringstream = std::basic_ostringstream<char, std::char_traits<char>, WorkingHeapAllocator<char>>;

template<typename T>
using WH_vector = std::vector<T, WorkingHeapAllocator<T>>;
