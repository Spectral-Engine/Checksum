// Checksum.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <iostream>
#include <string>
#include <Psapi.h>
#include <DbgHelp.h>
#include <iomanip>
#include <sstream>
DWORD TamperingCheck(LPCSTR path)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        return 0;
    }

    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == NULL)
    {
        CloseHandle(hFile);
        return 0;
    }

    LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == NULL)
    {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 0;
    }

    DWORD checksum = 0;
    PBYTE pBuffer = static_cast<PBYTE>(lpFileBase);

    for (DWORD i = 0; i < fileSize; i++)
    {
        checksum += *pBuffer++;
    }

    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    return checksum;
}

std::string IntToPattern(int value)
{
    std::string pattern;
    unsigned char* bytes = (unsigned char*)&value;

    for (int i = 0; i < sizeof(int); i++)
    {
        std::stringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
        pattern += ss.str();
        if (i < sizeof(int) - 1)
            pattern += " ";
    }

    return pattern;
}

std::string StringToPattern()
{
    
}

int main()
{
    std::string selected_tool;
    std::cout << "0) CPU Usage" << std::endl;
    std::cout << "1) Checksum" << std::endl;
    std::cout << "2) Int to Pattern" << std::endl;
    std::cout << "3) String to Pattern" << std::endl;
    std::getline(std::cin, selected_tool); 

    if (selected_tool == "0")
    {

        FILETIME idleTime, kernelTime, userTime;

        if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) { }
        double cpuUsage = 0.0;

        __int64 idleTimePrev = 0, kernelTimePrev = 0, userTimePrev = 0;
        __int64 idleTimeNow = 0, kernelTimeNow = 0, userTimeNow = 0;

        idleTimePrev = *(__int64*)&idleTime;
        kernelTimePrev = *(__int64*)&kernelTime;
        userTimePrev = *(__int64*)&userTime;

        Sleep(1000);

        if (GetSystemTimes(&idleTime, &kernelTime, &userTime))
        {
            idleTimeNow = *(__int64*)&idleTime;
            kernelTimeNow = *(__int64*)&kernelTime;
            userTimeNow = *(__int64*)&userTime;

            __int64 totalPrev = kernelTimePrev + userTimePrev;
            __int64 totalNow = kernelTimeNow + userTimeNow;
            __int64 total = totalNow - totalPrev;

            if (total > 0)
            {
                __int64 idlePrev = idleTimePrev;
                __int64 idleNow = idleTimeNow;
                __int64 idle = idleNow - idlePrev;

                cpuUsage = (double)(total - idle);
                cpuUsage = cpuUsage / total;
                cpuUsage = cpuUsage * 100.0;
                std::cout << "CPU Usage: " << cpuUsage << std::endl;
            }
        }
        system("pause");
    }

    if (selected_tool == "1")
    {
        std::cout << "Enter the dll path:" << std::endl;
        std::string dll_path;
        std::getline(std::cin, dll_path);
        std::cout << "Path: " << dll_path << std::endl;
        DWORD checksum = TamperingCheck(dll_path.c_str());
        std::cout << "Checksum: 0x" << std::hex << checksum << std::endl;
        system("pause");
    }
#undef max
    if (selected_tool == "2")
    {
        std::cout << "Enter the int:" << std::endl;
        int to_convert;
        std::cin >> to_convert;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string pattern = IntToPattern(to_convert);
        std::cout << "Pattern: " << pattern << std::endl;
        system("pause");
    }

    if (selected_tool == "3")
    {
        std::string to_convert;
        std::cout << "Enter a string:" << std::endl;
        std::getline(std::cin, to_convert);
        unsigned char* bytes = new unsigned char[to_convert.size() + 1];
        memcpy(bytes, to_convert.c_str(), to_convert.size() + 1);

        for (int i = 0; i < to_convert.size() + 1; i++) {
            std::cout << "0x" << std::hex << (int)bytes[i] << ", ";
        }
        std::cout << std::endl;

        delete[] bytes;
        system("pause");
    }
    return 0;
}

