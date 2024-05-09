// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Settings.h"
#include "WinapiHeap.h"
#include "Logger.h"

#include <Windows.h>

Settings g_settings;
Logger g_logger;
HANDLE g_hWorkingHeap = NULL;
HMODULE g_hDll = NULL;

DWORD WINAPI AnalyzeHeaps(LPVOID)
{
    g_logger.LogInfo("analyzing heaps for current process");

    HeapAnalyzer heapAnalyzer;
    HeapsStatistics heapsStats = heapAnalyzer.AnalyzeHeaps({ g_hWorkingHeap });
    g_logger.LogInfo("collected statistics for {} heaps", heapsStats.size());

    for (auto& s : heapsStats)
    {
        g_logger.LogInfo("heap stats: {}", s->ToString());
    }

    FreeLibraryAndExitThread(g_hDll, 0);
}

bool OnProcessAttach()
{
    g_hWorkingHeap = HeapCreate(0, 0, 0);
    if (g_hWorkingHeap == NULL)
        return false;

    g_logger.Init();
    g_logger.LogInfo("OnProcessAttach called! Working heap: {}", g_hWorkingHeap);

    HANDLE hThread = NULL;
    HANDLE hSharedMemory = NULL;
    Settings* sharedSettings = NULL;
    bool bRet = false;

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

        bRet = true;
    } while (false);

    if (hThread != NULL)
        CloseHandle(hThread);

    if (sharedSettings != NULL)
        UnmapViewOfFile(sharedSettings);

    if (hSharedMemory != NULL)
        CloseHandle(hSharedMemory);

    return bRet;
}

void OnProcessDetach()
{
    g_logger.LogInfo("OnProcessDetach called!");
    g_logger.Uninit();

    if (g_hWorkingHeap != NULL)
        HeapDestroy(g_hWorkingHeap);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hDll = hModule;
        return OnProcessAttach() == true ? TRUE : FALSE;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OnProcessDetach();
        break;
    }
    return TRUE;
}
