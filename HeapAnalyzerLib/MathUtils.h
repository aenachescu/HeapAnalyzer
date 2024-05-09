#pragma once

inline size_t Avg(size_t sum, size_t num)
{
    if (num == 0)
    {
        return 0;
    }

    return sum / num + (sum % num > 0 ? 1 : 0);
}
