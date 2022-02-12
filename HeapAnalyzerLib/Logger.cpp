#include "pch.h"
#include "Logger.h"

#include <chrono>
#include <thread>
#include <string>
#include <sstream>

void Logger::Init()
{
    SetModulePathAndName();

    std::string logPath = m_modulePath + "log.txt";

    m_hFile = CreateFileA(
        logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (m_hFile == INVALID_HANDLE_VALUE)
        return;

    m_pid = std::to_string(GetProcessId(GetCurrentProcess()));
    AddPaddingToString(m_pid, kPidSize);

    SetProcessName();

    m_bIsInitialized = true;

    LogMessage(LogLevel::info, "logger initialized!");
}

void Logger::Uninit()
{
    LogMessage(LogLevel::info, "uninitializing logger!");

    m_bIsInitialized = false;
    if (m_hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
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

    if (m_bIsInitialized == false)
        return;

    auto currentTime = std::chrono::system_clock::now();

    auto logMsg = std::format("[{}] [{}] [{}] [{}] [{} : {}] - {}\n",
        currentTime, LogLevelToString(lvl), m_processName, m_moduleName, m_pid, getCurrentThreadId(), msg);

    OVERLAPPED overlapped = { 0 };
    LockFileEx(m_hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped);
    WriteFile(m_hFile, logMsg.data(), static_cast<DWORD>(logMsg.size()), NULL, NULL);
    FlushFileBuffers(m_hFile);
    UnlockFileEx(m_hFile, 0, MAXDWORD, MAXDWORD, &overlapped);
}
