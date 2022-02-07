#include "pch.h"
#include "Logger.h"

#include <chrono>
#include <thread>
#include <string>
#include <sstream>

#include <Windows.h>

void Logger::Init()
{
    std::lock_guard<std::recursive_mutex> _lock(m_lock);

    SetModulePathAndName();

    std::string logPath = m_modulePath + "log.txt";

    m_file.open(logPath.data(), std::ios_base::app);
    if (!m_file)
        return;

    m_pid = std::to_string(GetProcessId(GetCurrentProcess()));
    AddPaddingToString(m_pid, kPidSize);

    SetProcessName();

    m_bIsInitialized = true;

    LogMessage(LogLevel::info, "logger initialized!");
}

void Logger::Uninit()
{
    std::lock_guard<std::recursive_mutex> _lock(m_lock);

    LogMessage(LogLevel::info, "uninitializing logger!");

    m_bIsInitialized = false;
    m_file.close();
}

void Logger::AddPaddingToString(std::string& str, size_t expectedSize)
{
    if (str.size() < expectedSize)
        str += std::string(expectedSize - str.size(), ' ');
}

void Logger::SetProcessName()
{
    char procName[MAX_PATH] = { 0 };

    if (GetModuleFileNameA(NULL, procName, sizeof(procName)) != 0)
    {
        m_processName = procName;

        auto found = m_processName.find_last_of('\\');
        if (found != std::string::npos)
            m_processName.erase(m_processName.begin(), m_processName.begin() + found + 1);

        AddPaddingToString(m_processName, kProcessNameSize);
    }
}

void Logger::SetModulePathAndName()
{
    static int addressInThisModule = 1;

    char moduleFileName[MAX_PATH];
    HMODULE hModule = NULL;

    bool bRes = GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&addressInThisModule,
        &hModule
    );

    if (bRes == FALSE)
        return;

    if (GetModuleFileNameA(hModule, moduleFileName, sizeof(moduleFileName)) == 0)
        return;

    m_modulePath = moduleFileName;

    auto found = m_modulePath.find_last_of('\\');
    if (found != std::string::npos)
    {
        m_moduleName = m_modulePath.substr(found + 1);
        m_modulePath.erase(m_modulePath.begin() + found + 1, m_modulePath.end());
    }
    else
    {
        m_moduleName = m_modulePath;
        m_modulePath = "";
    }

    AddPaddingToString(m_moduleName, kModuleNameSize);
}

const char* Logger::LogLevelToString(LogLevel lvl)
{
    switch (lvl)
    {
    case LogLevel::error:
        return "error";
    case LogLevel::info:
        return "info ";
    }

    return "-----";
}

void Logger::LogMessage(LogLevel lvl, const std::string& msg)
{
    auto getCurrentThreadId = [&]() -> std::string
    {
        std::ostringstream ss;
        ss << std::this_thread::get_id();

        std::string tidStr = ss.str();
        AddPaddingToString(tidStr, kTidSize);

        return tidStr;
    };

    std::lock_guard<std::recursive_mutex> _lock(m_lock);

    if (m_bIsInitialized == false)
        return;

    auto currentTime = std::chrono::system_clock::now();

    m_file << std::format("[{}] [{}] [{}] [{}] [{} : {}] - {}\n",
        currentTime, LogLevelToString(lvl), m_processName, m_moduleName, m_pid, getCurrentThreadId(), msg);
    m_file.flush();
}
