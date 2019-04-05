#include <iostream>
#include "DriverHelper.hpp"
#include <exception>

int main()
{
    DriverHelperMMap Driver;
    while (true)
    {
        getchar();
        Driver.SetCaptureModule(L"\\notepad.exe");
        getchar();
	    HANDLE ProcessId = Driver.GetTargetPid();
        printf("ProcessId: %d\n", ProcessId);
        getchar();
	    PVOID ClientAddress = Driver.GetModuleBase();
        printf("ClientAddress: 0x%llx\n", ClientAddress);
        getchar();
        INT32 bytes = Driver.ReadVirtualMemory<INT32>(ProcessId, (PVOID)((ULONGLONG)ClientAddress + 0x200FA), 4);
        printf("ReadVirtualMemory: 0x%08x\n", bytes);
        getchar();
        bytes ^= 0x0000FF00;
        Driver.WriteVirtualMemory(ProcessId, (PVOID)((ULONGLONG)ClientAddress + 0x200FA), bytes, 4);
        printf("WriteVirtualMemory: 0x%08x\n", bytes);
    }

    return 0;
}

