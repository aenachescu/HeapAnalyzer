// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Settings.h"
#include "Logger.h"
#include "WinapiHeap.h"

#include <Windows.h>

Settings g_settings;
Logger g_logger;
HANDLE g_hWorkingHeap = NULL;
HMODULE g_hDll = NULL;

DWORD WINAPI AnalyzeHeaps(LPVOID)
{
    g_logger.LogInfo("analyzing heaps for current process");

    do {
        g_hWorkingHeap = HeapCreate(0, 0, 0);
        if (g_hWorkingHeap == NULL)
        {
            g_logger.LogError("failed to create working heap: {}", GetLastError());
            break;
        }

        g_logger.LogInfo("working heap: {}", g_hWorkingHeap);

        WinapiHeap::HeapsStats heapsStats;
        WinapiHeap::HeapAnalyzer heapAnalyzer;

        bool bRes = heapAnalyzer.GetHeapsStatistics({ g_hWorkingHeap }, heapsStats);
        g_logger.LogInfo("got statistics for {} heaps: {}", heapsStats.size(), bRes);

        for (const auto& s : heapsStats)
            g_logger.LogInfo("heap stats:\n{}", s.ToString(g_settings.bStatsPerRegionLogging));
    } while (false);

    if (g_hWorkingHeap != NULL)
    {
        HeapDestroy(g_hWorkingHeap);
        g_hWorkingHeap = NULL;
    }

    FreeLibraryAndExitThread(g_hDll, 0);
}

void OnProcessAttach()
{
    g_logger.Init();
    g_logger.LogInfo("OnProcessAttach called!");

    HANDLE hThread = NULL;
    HANDLE hSharedMemory = NULL;
    Settings* sharedSettings = NULL;

    do {
        hSharedMemory = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, Settings::kSharedMemoryName);
        if (hSharedMemory == NULL)
        {
            g_logger.LogError("failed to open shared memory: {}", GetLastError());
            break;
        }

        sharedSettings = (Settings*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(Settings));
        if (sharedSettings == NULL)
        {
            g_logger.LogError("failed to map settings: {}", GetLastError());
            break;
        }

        memcpy(&g_settings, sharedSettings, sizeof(Settings));

        hThread = CreateThread(NULL, 0, AnalyzeHeaps, NULL, 0, NULL);
        if (hThread == NULL)
        {
            g_logger.LogError("Failed to create thread AnalyzeHeaps: {}", GetLastError());
            break;
        }
    } while (false);

    if (hThread != NULL)
        CloseHandle(hThread);

    if (sharedSettings != NULL)
        UnmapViewOfFile(sharedSettings);

    if (hSharedMemory != NULL)
        CloseHandle(hSharedMemory);
}

void OnProcessDetach()
{
    g_logger.LogInfo("OnProcessDetach called!");
    g_logger.Uninit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hDll = hModule;
        OnProcessAttach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OnProcessDetach();
        break;
    }
    return TRUE;
}
