// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Logger.h"
#include "WinapiHeap.h"

#include <Windows.h>

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
            g_logger.LogInfo("heap stats:\n{}", s.ToString());
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

    HANDLE hThread = CreateThread(NULL, 0, AnalyzeHeaps, NULL, 0, NULL);
    if (hThread == NULL)
    {
        g_logger.LogError("Failed to create thread AnalyzeHeaps: {}", GetLastError());
        return;
    }

    CloseHandle(hThread);
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