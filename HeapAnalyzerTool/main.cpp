#include "Logger.h"
#include "Allocator.h"
#include "WinapiHeap.h"

#include <Windows.h>

#include <string>
#include <iostream>

Logger g_logger;
HANDLE g_hWorkingHeap = NULL;

HANDLE g_hTestHeap = NULL;

void GenerateTestHeap()
{
    g_hTestHeap = HeapCreate(0, 0, 0);
    g_logger.LogInfo("test heap: {}", g_hTestHeap);

    auto v0 = HeapAlloc(g_hTestHeap, 0, 100);
    auto v1 = HeapAlloc(g_hTestHeap, 0, 101);
    auto v2 = HeapAlloc(g_hTestHeap, 0, 102);
    auto v3 = HeapAlloc(g_hTestHeap, 0, 103);
    auto v4 = HeapAlloc(g_hTestHeap, 0, 104);
    auto v5 = HeapAlloc(g_hTestHeap, 0, 105);
    auto v6 = HeapAlloc(g_hTestHeap, 0, 106);
    auto v7 = HeapAlloc(g_hTestHeap, 0, 107);
    auto v8 = HeapAlloc(g_hTestHeap, 0, 108);
    auto v9 = HeapAlloc(g_hTestHeap, 0, 109);

    HeapFree(g_hTestHeap, 0, v1);
    HeapFree(g_hTestHeap, 0, v2);
    HeapFree(g_hTestHeap, 0, v6);

    v1 = HeapAlloc(g_hTestHeap, 0, 70);
    v2 = HeapAlloc(g_hTestHeap, 0, 102);
    v6 = HeapAlloc(g_hTestHeap, 0, 99);

    auto v10 = HeapAlloc(g_hTestHeap, 0, 5000);
    auto v11 = HeapAlloc(g_hTestHeap, 0, 5001);
    auto v12 = HeapAlloc(g_hTestHeap, 0, 5002);
    auto v13 = HeapAlloc(g_hTestHeap, 0, 15001);
    auto v14 = HeapAlloc(g_hTestHeap, 0, 15002);
    auto v15 = HeapAlloc(g_hTestHeap, 0, 15003);

    //HeapFree(g_hTestHeap, 0, v10);
    //HeapFree(g_hTestHeap, 0, v11);
    //HeapFree(g_hTestHeap, 0, v12);
    //HeapFree(g_hTestHeap, 0, v13);
    //HeapFree(g_hTestHeap, 0, v14);
    //HeapFree(g_hTestHeap, 0, v15);

    auto v16 = HeapAlloc(g_hTestHeap, 0, 2123456);
    auto v17 = HeapAlloc(g_hTestHeap, 0, 2123457);
    auto v18 = HeapAlloc(g_hTestHeap, 0, 2123458);
    auto v19 = HeapAlloc(g_hTestHeap, 0, 2123459);
    HeapFree(g_hTestHeap, 0, v16);
}

void AnalyzeHeapsForThisProcess()
{
    g_logger.LogInfo("analyzing heaps for current process");

    do {
        g_hWorkingHeap = HeapCreate(0, 0, 0);
        if (g_hWorkingHeap == NULL)
        {
            g_logger.LogError("failed to create working heap: {}", GetLastError());
            break;
        }

        WinapiHeap::HeapsStats heapsStats;
        WinapiHeap::HeapAnalyzer heapAnalyzer;

        GenerateTestHeap();

        bool bRes = heapAnalyzer.GetHeapsStatistics({ g_hWorkingHeap }, heapsStats);
        g_logger.LogInfo("got statistics for {} heaps: {}", heapsStats.size(), bRes);

        for (const auto& s : heapsStats)
            g_logger.LogInfo("heap stats:\n{}", s.ToString());
    } while (false);

    if (g_hWorkingHeap != NULL)
    {
        HeapDestroy(g_hWorkingHeap);
        g_hWorkingHeap = NULL;
    }
}

void AnalyzeHeapsForProcess(DWORD pid)
{
    static constexpr char kDllName[] = "HeapAnalyzerDll.dll";

    char moduleFileName[MAX_PATH];
    std::string dllPath;
    void* dllPathRemote = NULL;
    HANDLE hThread = NULL;
    HMODULE hKernel32 = NULL;
    HANDLE hProcess = NULL;
    BOOL bRes = FALSE;

    do {
        if (GetModuleFileNameA(NULL, moduleFileName, sizeof(moduleFileName)) == 0)
        {
            g_logger.LogError("failed to get module filename: {}", GetLastError());
            break;
        }

        // calculate dll path
        {
            dllPath = moduleFileName;
            auto found = dllPath.find_last_of('\\');
            if (found != std::string::npos)
            {
                dllPath.erase(dllPath.begin() + found + 1, dllPath.end());
                dllPath += kDllName;
            }
            else
            {
                dllPath = kDllName;
            }

            g_logger.LogInfo("dll path: [{}]", dllPath);
        }

        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess == NULL)
        {
            g_logger.LogError("failed to open process: {}", GetLastError());
            break;
        }

        hKernel32 = GetModuleHandleA("Kernel32");
        if (hKernel32 == NULL)
        {
            g_logger.LogError("failed to get Kernel32: {}", GetLastError());
            break;
        }

        dllPathRemote = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
        if (dllPathRemote == NULL)
        {
            g_logger.LogError("failed to alloc remote dllPath: {}", GetLastError());
            break;
        }

        bRes = WriteProcessMemory(hProcess, dllPathRemote, (void*)dllPath.data(), dllPath.size() + 1, NULL);
        if (bRes == FALSE)
        {
            g_logger.LogError("failed to write remote dllPath", GetLastError());
            break;
        }

        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"),
            dllPathRemote, 0, NULL);
        if (hThread == NULL)
        {
            g_logger.LogError("failed to create remote thread: {}", GetLastError());
            break;
        }

        auto r = WaitForSingleObject(hThread, INFINITE);
        g_logger.LogInfo("wait for remote thread: {}", r);
    } while (false);

    if (hThread != NULL)
        CloseHandle(hThread);

    if (dllPathRemote != NULL)
        VirtualFreeEx(hProcess, dllPathRemote, 0, MEM_RELEASE);

    if (hProcess != NULL)
        CloseHandle(hProcess);
}

void DllInjectorTest()
{
    g_logger.LogInfo("dll injector test");
    GenerateTestHeap();
    std::string s;
    std::cin >> s;
}

int main(int argc, const char** argv)
{
    g_logger.Init();

    if (argc > 1)
    {
        if (strcmp("thisProcess", argv[1]) == 0)
        {
            AnalyzeHeapsForThisProcess();
        }
        else if (strcmp("remoteProcess", argv[1]) == 0)
        {
            if (argc > 2)
            {
                DWORD pid = std::strtoul(argv[2], NULL, 10);
                AnalyzeHeapsForProcess(pid);
            }
            else
            {
                g_logger.LogError("no pid for remote process");
            }
        }
        else if (strcmp("dllInjectorTest", argv[1]) == 0)
        {
            DllInjectorTest();
        }
        else
        {
            g_logger.LogError("unknown command: [{}]", argv[1]);
        }
    }
    else
        g_logger.LogError("no command");

    g_logger.Uninit();
    return 0;
}