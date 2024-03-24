#pragma once

#include "Allocator.h"

#include <type_traits>

template<typename T, std::enable_if_t<std::is_integral<T>::value&& std::is_unsigned<T>::value, bool> = true>
static WH_string to_wh_string(T val)
{
    char buff[64] = { '\0' };
    char* buffEnd = std::end(buff);
    char* revIt = buffEnd;

    do {
        --revIt;
        *revIt = static_cast<char>('0' + val % 10);
        val /= 10;
    } while (val != 0);

    return WH_string(revIt, buffEnd);
}
