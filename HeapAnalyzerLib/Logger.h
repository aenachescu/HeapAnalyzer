#pragma once

#include <string_view>
#include <string>
#include <format>

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

public:
    Logger() = default;
    ~Logger() = default;

    void Init();
    void Uninit();

    template<typename... Args>
    void LogError(std::string_view fmt, Args&&... args)
    {
        LogMessage(LogLevel::error, std::vformat(fmt, std::make_format_args(args...)));
    }

    template<typename... Args>
    void LogInfo(std::string_view fmt, Args&&... args)
    {
        LogMessage(LogLevel::info, std::vformat(fmt, std::make_format_args(args...)));
    }

private:
    void AddPaddingToString(std::string& str, size_t expectedSize);
    void SetProcessName();
    void SetModulePathAndName();
    const char* LogLevelToString(LogLevel lvl);
    void LogMessage(LogLevel lvl, const std::string& msg);

private:
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    bool m_bIsInitialized = false;
    std::string m_processName = "<unknown>";
    std::string m_moduleName = "<unknown>";
    std::string m_modulePath;
    std::string m_pid = std::string("0") + std::string(kPidSize - 1, ' ');
};
