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
    static constexpr size_t kProcessNameSize = 25;
    static constexpr size_t kModuleNameSize = 25;

    struct Strings
    {
        WH_string m_processName = "<unknown>";
        WH_string m_moduleName = "<unknown>";
        WH_string m_modulePath;
        WH_string m_pid = WH_string("0") + WH_string(kPidSize - 1, ' ');
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
    // Logger class is initialized as a global variable so the ctor will be called before main function
    // the working heap is initialized in main function, so it isn't ready for use when all WH_strings
    // will be constructed.
    WH_unique_ptr<Strings> m_pStrings = nullptr;
};
