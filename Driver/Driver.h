#pragma once

// ------------------------------------ EDITABLE -----------------------------------------

#define DRIVER_DEVICE_NAME              L"kernelhop"
#define DEFAULT_CAPTURE_MODULE_NAME     L"\\notepad++.exe"

#define MMAP_SECTION_NAME               L"RandomSharedMemory"
#define MMAP_SECTION_SIZE               sizeof(MMAP_IO_REQUEST)   // this should be enough for any proper request

#define SYNC_EVENT_NAME                 L"SimIOFastEvent"

// ---------------------------------------------------------------------------------------

#define CC_READ_MEMORY                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CC_WRITE_MEMORY                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CC_GET_PID                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CC_GET_MOD_BASE                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CC_REFRESH_PROCESS              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CC_SET_CAPTURE_MODULE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0706, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// ------------------------------------ DO NOT TOUCH ------------------------------------------

typedef struct _KERNEL_RW_MEM_REQUEST
{
    HANDLE      ProcessId;
    PVOID       Address;
    ULONGLONG   Value;  // max buffer size: 8 byte
    SIZE_T      Size;

} KERNEL_RW_MEM_REQUEST, *PKERNEL_RW_MEM_REQUEST;


typedef struct _MMAP_IO_REQUEST
{
    INT         ControlCode;
    union       _SystemBuffer
    {
        KERNEL_RW_MEM_REQUEST RWMem;
        HANDLE                Pid;
        PVOID                 BaseAddress;
        WCHAR                 ModuleName[512];
    }SystemBuffer;
    
} MMAP_IO_REQUEST, *PMMAP_IO_REQUEST;

#ifndef _DEBUG
#define DbgPrintEx
#endif