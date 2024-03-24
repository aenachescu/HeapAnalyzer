#pragma once

#include <string_view>
#include <format>
#include <memory>

#include "Allocator.h"

#include <Windows.h>

class Logger
{
private:
    enum class LogLevel
    {
        info,
        error,
    };

    static constexpr size_t kPidSize = 5;
    static constexpr size_t kTidSize = 5;
    static constexpr size_t kProcessNameSize = 25;
    static constexpr size_t kModuleNameSize = 25;

    struct Strings
    {
        WH_string m_processName = "<unknown>";
        WH_string m_moduleName = "<unknown>";
        WH_string m_modulePath;
        WH_string m_pid = WH_string("0") + WH_string(kPidSize - 1, ' ');

        struct Deleter
        {
            void operator()(Strings* s)
            {
                if (s != nullptr)
                {
                    WorkingHeapAllocator<Strings> a;
                    a.deallocate(s, 1);
                }
            }
        };
    };

public:
    Logger() = default;
    ~Logger() = default;

    void Init();
    void Uninit();

    template<typename... Args>
    void LogError(std::string_view fmt, Args&&... args)
    {
        WH_string msg;
        std::vformat_to(std::back_inserter(msg), fmt, std::make_format_args(args...));
        LogMessage(LogLevel::error, msg);
    }

    template<typename... Args>
    void LogInfo(std::string_view fmt, Args&&... args)
    {
        WH_string msg;
        std::vformat_to(std::back_inserter(msg), fmt, std::make_format_args(args...));
        LogMessage(LogLevel::info, msg);
    }

private:
    void AddPaddingToString(WH_string& str, size_t expectedSize);
    void SetProcessName();
    void SetModulePathAndName();
    const char* LogLevelToString(LogLevel lvl);
    void LogMessage(LogLevel lvl, const WH_string& msg);

private:
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    bool m_bIsInitialized = false;
    std::unique_ptr<Strings, Strings::Deleter> m_pStrings = nullptr;
};
