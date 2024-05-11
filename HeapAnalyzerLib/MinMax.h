#pragma once

#include <limits>
#include <type_traits>

template<typename StorageType = size_t>
struct Counter
{
public:
    Counter() noexcept = default;
    ~Counter() noexcept = default;

    StorageType getCounter() const
    {
        return counter;
    }

protected:
    void count(StorageType c = 1)
    {
        counter += c;
    }

    void reset(StorageType c = std::numeric_limits<StorageType>::min() + 1)
    {
        counter = c;
    }

private:
    StorageType counter = std::numeric_limits<StorageType>::min();
};

struct EmptyCounter
{
};

template<typename StorageType, typename CounterType>
struct MaxValueT : public CounterType
{
public:
    MaxValueT() noexcept = default;
    ~MaxValueT() noexcept = default;

    StorageType getValue() const
    {
        return value;
    }

    MaxValueT& operator=(const StorageType& val)
    {
        if (value == val)
            CounterType::count();
        else if (val > value)
        {
            CounterType::reset();
            value = val;
        }

        return *this;
    }

    MaxValueT& operator=(const MaxValueT& val)
    {
        if (value == val.value)
            CounterType::count(val.getCounter());
        else if (val.value > value)
        {
            CounterType::reset(val.getCounter());
            value = val.value;
        }

        return *this;
    }

    MaxValueT& operator=(const MaxValueT<StorageType, EmptyCounter>& val)
    {
        if (value == val.getValue())
            CounterType::count();
        else if (val.getValue() > value)
        {
            CounterType::reset();
            value = val.getValue();
        }

        return *this;
    }
private:
    StorageType value = std::numeric_limits<StorageType>::min();
};

template<typename StorageType>
struct MaxValueT<StorageType, EmptyCounter>
{
public:
    MaxValueT() noexcept = default;
    ~MaxValueT() noexcept = default;

    StorageType getValue() const
    {
        return value;
    }

    MaxValueT& operator=(const StorageType& val)
    {
        if (val > value)
            value = val;

        return *this;
    }
private:
    StorageType value = std::numeric_limits<StorageType>::min();
};

template<typename StorageType = size_t, typename CounterStorageType = size_t>
using MaxValueAndCountT = MaxValueT<StorageType, Counter<CounterStorageType>>;

using MaxValueAndCount = MaxValueAndCountT<>;

//-----------------------------------------------------------------------------

template<typename StorageType, typename CounterType>
struct MinValueT : public CounterType
{
public:
    MinValueT() noexcept = default;
    ~MinValueT() noexcept = default;

    StorageType getValue() const
    {
        return value;
    }

    MinValueT& operator=(const StorageType& val)
    {
        if (value == val)
            CounterType::count();
        else if (val < value)
        {
            CounterType::reset();
            value = val;
        }

        return *this;
    }

    MinValueT& operator=(const MinValueT& val)
    {
        if (value == val.value)
            CounterType::count(val.getCounter());
        else if (val.value < value)
        {
            CounterType::reset(val.getCounter());
            value = val.value;
        }

        return *this;
    }

    MinValueT& operator=(const MinValueT<StorageType, EmptyCounter>& val)
    {
        if (value == val.getValue())
            CounterType::count();
        else if (val.getValue() < value)
        {
            CounterType::reset();
            value = val.getValue();
        }

        return *this;
    }

private:
    StorageType value = std::numeric_limits<StorageType>::max();
};

template<typename StorageType>
struct MinValueT<StorageType, EmptyCounter>
{
public:
    MinValueT() noexcept = default;
    ~MinValueT() noexcept = default;

    StorageType getValue() const
    {
        return value;
    }

    MinValueT& operator=(const StorageType& val)
    {
        if (val < value)
            value = val;

        return *this;
    }
private:
    StorageType value = std::numeric_limits<StorageType>::max();
};

template<typename StorageType = size_t, typename CounterStorageType = size_t>
using MinValueAndCountT = MinValueT<StorageType, Counter<CounterStorageType>>;

using MinValueAndCount = MinValueAndCountT<>;
