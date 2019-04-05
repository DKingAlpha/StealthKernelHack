#include <Windows.h>

#include "..\Driver\Driver.h"

#include <strsafe.h>


class DriverHelperIoCtl
{
public:
	HANDLE hDriver;

    DriverHelperIoCtl(LPCWSTR RegistryPath)
	{
		hDriver = CreateFileW(RegistryPath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	template <typename type>
	type ReadVirtualMemory(HANDLE ProcessId, PVOID ReadAddress,
		SIZE_T Size)
	{
		if (hDriver == INVALID_HANDLE_VALUE) return (type)false;

        KERNEL_RW_MEM_REQUEST ReadRequest;

		ReadRequest.ProcessId = ProcessId;
		ReadRequest.Address = ReadAddress;
		ReadRequest.Size = Size;

		if (DeviceIoControl(hDriver, CC_READ_MEMORY, &ReadRequest,
			sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))
			return (type)ReadRequest.Value;
		else
			return (type)false;
	}

	bool WriteVirtualMemory(HANDLE ProcessId, PVOID WriteAddress,
		ULONGLONG WriteValue, SIZE_T WriteSize)
	{
		if (hDriver == INVALID_HANDLE_VALUE) return false;
		DWORD Bytes;

        KERNEL_RW_MEM_REQUEST  WriteRequest;
		WriteRequest.ProcessId = ProcessId;
		WriteRequest.Address = WriteAddress;
		WriteRequest.Value = WriteValue;
		WriteRequest.Size = WriteSize;

		if (DeviceIoControl(hDriver, CC_WRITE_MEMORY, &WriteRequest, sizeof(WriteRequest), 0, 0, &Bytes, NULL))
			return true;
		else
			return false;
	}

	HANDLE GetTargetPid()
	{
		if (hDriver == INVALID_HANDLE_VALUE) return false;

        HANDLE Pid;
		DWORD Bytes;

		if (DeviceIoControl(hDriver, CC_GET_PID, &Pid, sizeof(Pid),
			&Pid, sizeof(Pid), &Bytes, NULL))
			return Pid;
		else
			return 0;
	}

	PVOID GetModuleBase()
	{
		if (hDriver == INVALID_HANDLE_VALUE) return false;

        PVOID Address;
		DWORD Bytes;

		if (DeviceIoControl(hDriver, CC_GET_MOD_BASE, &Address, sizeof(Address),
			&Address, sizeof(Address), &Bytes, NULL))
			return Address;
		else
			return false;
	}
};




class DriverHelperMMap
{
public:
    HANDLE hMapFile = 0;
    char *sharedMemory = 0;
    HANDLE newReqEvent = NULL, finishedEvent = NULL;
    BOOLEAN inited = FALSE;

#define ASSERT_VALID(v) if(v==NULL){printf("Failed at " #v " , Error: 0x%x", GetLastError());  return;}

    DriverHelperMMap()
    {
        hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
            MMAP_SECTION_SIZE, L"Global\\" MMAP_SECTION_NAME);
        ASSERT_VALID(hMapFile);

        sharedMemory = (char *)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, MMAP_SECTION_SIZE);
        ASSERT_VALID(sharedMemory);

        newReqEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\" SYNC_EVENT_NAME L"1");
        ASSERT_VALID(newReqEvent);

        finishedEvent = CreateEvent(NULL, FALSE, FALSE, L"Global\\" SYNC_EVENT_NAME L"2");
        ASSERT_VALID(finishedEvent);

        inited = TRUE;
    }

    ~DriverHelperMMap()
    {
        CloseHandle(finishedEvent);
        CloseHandle(newReqEvent);
        UnmapViewOfFile(sharedMemory);
        CloseHandle(hMapFile);
    }

    VOID ManualUnload()
    {
        if (!inited) return;
        CopyMemory(sharedMemory, "exit", 4);
    }
    
    template <typename type>
    type ReadVirtualMemory(HANDLE ProcessId, PVOID ReadAddress,
        SIZE_T Size)
    {
        if (!inited) return (type)false;

        // pack & write request
        PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
        ioreq->ControlCode = CC_READ_MEMORY;
        ioreq->SystemBuffer.RWMem.ProcessId = ProcessId;
        ioreq->SystemBuffer.RWMem.Address = ReadAddress;
        ioreq->SystemBuffer.RWMem.Size = Size;

        // notify kernel
        SetEvent(newReqEvent);
        // wait for kernel reset event
        WaitForSingleObject(finishedEvent, INFINITE);
        // now retrieve result
        type result = (type)ioreq->SystemBuffer.RWMem.Value;
        // clean buffer
        ZeroMemory(sharedMemory, MMAP_SECTION_SIZE);

        return result;
    }

    BOOLEAN WriteVirtualMemory(HANDLE ProcessId, PVOID WriteAddress,
        ULONGLONG WriteValue, SIZE_T Size)
    {
        if (!inited) return FALSE;

        // pack & write request
        PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
        ioreq->ControlCode = CC_WRITE_MEMORY;
        ioreq->SystemBuffer.RWMem.ProcessId = ProcessId;
        ioreq->SystemBuffer.RWMem.Address = WriteAddress;
        ioreq->SystemBuffer.RWMem.Value = WriteValue;
        ioreq->SystemBuffer.RWMem.Size = Size;

        // notify kernel
        SetEvent(newReqEvent);
        // wait for kernel reset event
        WaitForSingleObject(finishedEvent, INFINITE);
        // now retrieve result
        // ... nothing to do
        // clean buffer
        ZeroMemory(sharedMemory, MMAP_SECTION_SIZE);

        return TRUE;
    }

    HANDLE GetTargetPid()
    {
        if (!inited) return NULL;

        // pack & write request
        PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
        ioreq->ControlCode = CC_GET_PID;

        // notify kernel
        SetEvent(newReqEvent);
        // wait for kernel reset event
        WaitForSingleObject(finishedEvent, INFINITE);
        // now retrieve result
        HANDLE result = ioreq->SystemBuffer.Pid;
        // clean buffer
        ZeroMemory(sharedMemory, MMAP_SECTION_SIZE);

        return result;
    }

    PVOID GetModuleBase()
    {
        if (!inited) return NULL;

        // pack & write request
        PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
        ioreq->ControlCode = CC_GET_MOD_BASE;

        // notify kernel
        SetEvent(newReqEvent);
        // wait for kernel reset event
        WaitForSingleObject(finishedEvent, INFINITE);
        // now retrieve result
        HANDLE result = ioreq->SystemBuffer.BaseAddress;
        // clean buffer
        ZeroMemory(sharedMemory, MMAP_SECTION_SIZE);
        return result;
    }

    BOOLEAN SetCaptureModule(LPCWSTR ModuleName)
    {
        if (!inited) return FALSE;

        // pack & write request
        PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
        ioreq->ControlCode = CC_SET_CAPTURE_MODULE;
        StringCchCopyW(ioreq->SystemBuffer.ModuleName, 512, ModuleName);

        // notify kernel
        SetEvent(newReqEvent);
        // wait for kernel reset event
        WaitForSingleObject(finishedEvent, INFINITE);
        // now retrieve result
        // ... nothing to do
        // clean buffer
        ZeroMemory(sharedMemory, MMAP_SECTION_SIZE);
        return TRUE;
    }
};
