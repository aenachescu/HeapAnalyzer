#include "Settings.h"
#include "Logger.h"
#include "Allocator.h"
#include "HeapAnalyzer.h"

#include <Windows.h>

#include <string>
#include <iostream>

Settings g_settings;
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

    GenerateTestHeap();

    HeapAnalyzer heapAnalyzer;
    HeapsStatistics heapsStats = heapAnalyzer.AnalyzeHeaps({ g_hWorkingHeap });

    g_logger.LogInfo("collected statistics for {} heaps", heapsStats.size());

    for (auto& s : heapsStats)
    {
        g_logger.LogInfo("heap stats:\n{}", s->ToString(g_settings.bStatsPerRegionLogging));
    }
}

void AnalyzeHeapsForProcess(DWORD pid)
{
    static constexpr char kDllName[] = "HeapAnalyzerDll.dll";

    char moduleFileName[MAX_PATH];
    WH_string dllPath;
    void* dllPathRemote = NULL;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    HANDLE hSharedMemory = NULL;
    HMODULE hKernel32 = NULL;
    Settings* sharedSettings = NULL;
    DWORD exitCode = 0;
    DWORD waitRes = WAIT_FAILED;
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

        hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(Settings), Settings::kSharedMemoryName);
        if (hSharedMemory == NULL)
        {
            g_logger.LogError("failed to create shared memory: {}", GetLastError());
            break;
        }

        sharedSettings = (Settings*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Settings));
        if (sharedSettings == NULL)
        {
            g_logger.LogError("failed to map settings: {}", GetLastError());
            break;
        }

        memcpy(sharedSettings, &g_settings, sizeof(Settings));

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

        waitRes = WaitForSingleObject(hThread, INFINITE);
        if (waitRes != WAIT_OBJECT_0)
        {
            g_logger.LogError("wait for remote thread failed: {}", waitRes);
            break;
        }

        bRes = GetExitCodeThread(hThread, &exitCode);
        if (bRes == FALSE)
        {
            g_logger.LogError("failed to get remote thread exit code: {}", GetLastError());
            break;
        }

        if (exitCode == 0)
        {
            g_logger.LogError("failed to inject dll");
        }
        else
        {
            g_logger.LogInfo("dll injected successfully");
        }
    } while (false);

    if (hThread != NULL)
        CloseHandle(hThread);

    if (dllPathRemote != NULL)
        VirtualFreeEx(hProcess, dllPathRemote, 0, MEM_RELEASE);

    if (hProcess != NULL)
        CloseHandle(hProcess);

    if (sharedSettings != NULL)
        UnmapViewOfFile(sharedSettings);

    if (hSharedMemory != NULL)
        CloseHandle(hSharedMemory);
}

void DllInjectorTest()
{
    g_logger.LogInfo("dll injector test");
    GenerateTestHeap();
    WH_string s;
    std::cin >> s;
}

void ParseSettings(int argc, const char** argv, int start)
{
    for (int i = start; i < argc; i++)
    {
        if (strcmp("StatsPerRegionLogging", argv[i]) == 0)
        {
            g_settings.bStatsPerRegionLogging = true;
        }
        else if (strcmp("HeapEntryLogging", argv[i]) == 0)
        {
            g_settings.bHeapEntryLogging = true;
        }
        else if (strcmp("SearchStrings", argv[i]) == 0)
        {
            g_settings.bSearchStrings = true;
        }
        else
        {
            g_logger.LogError("unknown setting: [{}]", argv[i]);
        }
    }
}

int main(int argc, const char** argv)
{
    g_hWorkingHeap = HeapCreate(0, 0, 0);
    if (g_hWorkingHeap == NULL)
    {
        std::cout << "failed to create working heap: " << GetLastError() << std::endl;
        return 1;
    }

    g_logger.Init();
    g_logger.LogInfo("Working heap: {}", g_hWorkingHeap);

    if (argc > 1)
    {
        if (strcmp("thisProcess", argv[1]) == 0)
        {
            ParseSettings(argc, argv, 2);
            AnalyzeHeapsForThisProcess();
        }
        else if (strcmp("remoteProcess", argv[1]) == 0)
        {
            if (argc > 2)
            {
                DWORD pid = std::strtoul(argv[2], NULL, 10);
                ParseSettings(argc, argv, 3);
                AnalyzeHeapsForProcess(pid);
            }
            else
            {
                g_logger.LogError("no pid for remote process");
            }
        }
        else if (strcmp("dllInjectorTest", argv[1]) == 0)
        {
            ParseSettings(argc, argv, 2);
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
    HeapDestroy(g_hWorkingHeap);

    return 0;
}