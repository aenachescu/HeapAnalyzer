#include "pch.h"
#include "Logger.h"
#include "StringUtils.h"

#include <chrono>
#include <thread>
#include <string>
#include <sstream>

void Logger::Init()
{
    m_pStrings = std::unique_ptr<Strings, Strings::Deleter>{ WorkingHeapAllocator<Strings>().allocate(1) };

    SetModulePathAndName();

    WH_string logPath = m_pStrings->m_modulePath + "HeapAnalyzer.log";

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

    m_pStrings->m_pid = ToWHString(GetProcessId(GetCurrentProcess()));
    AddPaddingToString(m_pStrings->m_pid, kPidSize);

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

    m_pStrings.reset();
}

void Logger::AddPaddingToString(WH_string& str, size_t expectedSize)
{
    if (str.size() < expectedSize)
        str += WH_string(expectedSize - str.size(), ' ');
}

void Logger::SetProcessName()
{
    char procName[MAX_PATH] = { 0 };

    if (GetModuleFileNameA(NULL, procName, sizeof(procName)) != 0)
    {
        m_pStrings->m_processName = procName;

        auto found = m_pStrings->m_processName.find_last_of('\\');
        if (found != WH_string::npos)
            m_pStrings->m_processName.erase(m_pStrings->m_processName.begin(), m_pStrings->m_processName.begin() + found + 1);

        AddPaddingToString(m_pStrings->m_processName, kProcessNameSize);
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

    m_pStrings->m_modulePath = moduleFileName;

    auto found = m_pStrings->m_modulePath.find_last_of('\\');
    if (found != WH_string::npos)
    {
        m_pStrings->m_moduleName = m_pStrings->m_modulePath.substr(found + 1);
        m_pStrings->m_modulePath.erase(m_pStrings->m_modulePath.begin() + found + 1, m_pStrings->m_modulePath.end());
    }
    else
    {
        m_pStrings->m_moduleName = m_pStrings->m_modulePath;
        m_pStrings->m_modulePath = "";
    }

    AddPaddingToString(m_pStrings->m_moduleName, kModuleNameSize);
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

void Logger::LogMessage(LogLevel lvl, const WH_string& msg)
{
    auto getCurrentThreadId = [&]() -> WH_string
    {
        WH_ostringstream ss;
        ss << std::this_thread::get_id();

        WH_string tidStr = ss.str();
        AddPaddingToString(tidStr, kTidSize);

        return tidStr;
    };

    if (m_bIsInitialized == false)
        return;

    auto currentTime = std::chrono::system_clock::now();

    WH_string logMsg;
    std::format_to(std::back_inserter(logMsg), "[{}] [{}] [{}] [{}] [{} : {}] - {}\n",
        currentTime,
        LogLevelToString(lvl),
        m_pStrings->m_processName,
        m_pStrings->m_moduleName,
        m_pStrings->m_pid,
        getCurrentThreadId(),
        msg);

    OVERLAPPED overlapped = { 0 };
    LockFileEx(m_hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped);
    WriteFile(m_hFile, logMsg.data(), static_cast<DWORD>(logMsg.size()), NULL, NULL);
    FlushFileBuffers(m_hFile);
    UnlockFileEx(m_hFile, 0, MAXDWORD, MAXDWORD, &overlapped);
}
