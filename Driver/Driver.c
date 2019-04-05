#include <ntdef.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver.h"

// internal, auto linked
NTSTATUS NTAPI MmCopyVirtualMemory
(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);


PDEVICE_OBJECT pDeviceObject; // our driver object
UNICODE_STRING dev, dos; // Driver registry paths

HANDLE mmapThreadHandle;

HANDLE TargetPid;
PVOID  TargetBaseAddress;
PEPROCESS ProcessCache;

WCHAR CaptureModuleName[512];



void ImageLoadCallback(PUNICODE_STRING FullImageName,
    HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if (*CaptureModuleName == 0)
    {
        RtlCopyMemory(CaptureModuleName, DEFAULT_CAPTURE_MODULE_NAME, sizeof(DEFAULT_CAPTURE_MODULE_NAME));
    }
    if (wcsstr(FullImageName->Buffer, CaptureModuleName))
    {
        DbgPrintEx(0, 0, "Loaded Name: %ls \n", FullImageName->Buffer);
        DbgPrintEx(0, 0, "Loaded Pid:  %d \n", ProcessId);

        TargetBaseAddress = ImageInfo->ImageBase;
        TargetPid = ProcessId;
    }
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
    DbgPrintEx(0, 0, "Unload routine called.\n");

    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    IoDeleteSymbolicLink(&dos);
    IoDeleteDevice(pDriverObject->DeviceObject);
    return STATUS_SUCCESS;
}

NTSTATUS CreateCloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// stealth mem r/w
// NtReadVirtualMemory/NtWriteVirtualMemory might have been hooked by AC

NTSTATUS AltReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
    return MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes);
}

NTSTATUS AltWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes);
}

// compatibility for mmap io

NTSTATUS DoIoControl(ULONG IoControlCode, PVOID Buffer, PULONG BytesIO)
{
    NTSTATUS Status = STATUS_SUCCESS;

    // Code received from user space
    PKERNEL_RW_MEM_REQUEST RWBuffer = (PKERNEL_RW_MEM_REQUEST)Buffer;

    switch (IoControlCode)
    {
    case CC_READ_MEMORY:
        if (RWBuffer->ProcessId != TargetPid)
        {
            if (ProcessCache)
            {
                ObDereferenceObject(ProcessCache);
                ProcessCache = NULL;
            }
            PsLookupProcessByProcessId(RWBuffer->ProcessId, &ProcessCache);
        }
        else
        {
            if (!ProcessCache)
            {
                PsLookupProcessByProcessId(RWBuffer->ProcessId, &ProcessCache);
            }
        }

        // still not found process
        if (ProcessCache)
        {
            Status = AltReadVirtualMemory(ProcessCache, RWBuffer->Address, &RWBuffer->Value, RWBuffer->Size);
            *BytesIO = sizeof(RWBuffer);
        }
        else
        {
            Status = STATUS_INVALID_HANDLE;
            *BytesIO = 0;
        }

        DbgPrintEx(0, 0, "AltReadVirtualMemory-> Pid: %lu, Address: %p, Value: 0x%llx, Result: %x\n", RWBuffer->ProcessId, RWBuffer->Address, RWBuffer->Value, Status);
        break;

    case CC_WRITE_MEMORY:
        if (RWBuffer->ProcessId != TargetPid)
        {
            if (ProcessCache)
            {
                ObDereferenceObject(ProcessCache);
                ProcessCache = NULL;
            }
            PsLookupProcessByProcessId(RWBuffer->ProcessId, &ProcessCache);
        }
        else
        {
            if (!ProcessCache)
            {
                PsLookupProcessByProcessId(RWBuffer->ProcessId, &ProcessCache);
            }
        }

        // still not found process
        if (ProcessCache)
        {
            Status = AltWriteVirtualMemory(ProcessCache, &RWBuffer->Value, RWBuffer->Address, RWBuffer->Size);
            *BytesIO = sizeof(RWBuffer);
        }
        else
        {
            Status = STATUS_INVALID_HANDLE;
            *BytesIO = 0;
        }

        DbgPrintEx(0, 0, "AltWriteVirtualMemory-> Pid: %lu, Address: %p, Value: 0x%llx, Result: %x\n", RWBuffer->ProcessId, RWBuffer->Address, RWBuffer->Value, Status);
        break;

    case CC_GET_PID:
        RtlCopyMemory(Buffer, &TargetPid, sizeof(TargetPid));
        DbgPrintEx(0, 0, "get pid %d", *(PHANDLE)Buffer);
        Status = STATUS_SUCCESS;
        *BytesIO = sizeof(TargetPid);
        break;

    case CC_GET_MOD_BASE:
        RtlCopyMemory(Buffer, &TargetBaseAddress, sizeof(TargetBaseAddress));
        DbgPrintEx(0, 0, "get module 0x%llx\n", *(PULONGLONG)Buffer);
        Status = STATUS_SUCCESS;
        *BytesIO = sizeof(TargetBaseAddress);
        break;

    case CC_REFRESH_PROCESS:
        if (ProcessCache)
        {
            ObDereferenceObject(ProcessCache);
            ProcessCache = NULL;
        }
        break;

    case CC_SET_CAPTURE_MODULE:
        RtlStringCchCopyW(CaptureModuleName, 512, (PCWSTR)Buffer);
        DbgPrintEx(0, 0, "Capture Module base of: %S\n", CaptureModuleName);
        break;

    default:
        // if the code is unknown
        Status = STATUS_INVALID_PARAMETER;
        *BytesIO = 0;
        break;
    }
    return Status;
}


// IOCTL Call Handler function
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_SUCCESS;
	ULONG BytesIO = 0;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    Status = DoIoControl(stack->Parameters.DeviceIoControl.IoControlCode, Irp->AssociatedIrp.SystemBuffer, &BytesIO);

	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}


void SetupMMapIo(PVOID v)
{
    UNREFERENCED_PARAMETER(v);
    DbgPrintEx(0, 0, "Running as manual mapped code\n");
    NTSTATUS status;
    PVOID sharedMemory = NULL;
    SIZE_T vs = MMAP_SECTION_SIZE;
    OBJECT_ATTRIBUTES myAttributes;
    UNICODE_STRING sectionName;
    RtlInitUnicodeString(&sectionName, L"\\BaseNamedObjects\\" MMAP_SECTION_NAME);
    HANDLE sectionHandle;
    InitializeObjectAttributes(&myAttributes, &sectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenSection(&sectionHandle, SECTION_ALL_ACCESS, &myAttributes);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ZwOpenSection. 0x%x\n", status); return; }

    status = ZwMapViewOfSection(sectionHandle, (HANDLE)ZwCurrentProcess(), &sharedMemory, 0, 0,
        NULL, &vs, ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ZwMapViewOfSection. 0x%x\n", status); return; }

    UNICODE_STRING incomingEventName, finishEventName;
    OBJECT_ATTRIBUTES incoming_obj_attr, finish_obj_attr;
    HANDLE incomingEventHandle, finishEventHandle;
    PKEVENT incomingEvent, finishEvent;

    RtlInitUnicodeString(&incomingEventName, L"\\BaseNamedObjects\\" SYNC_EVENT_NAME L"1");
    RtlInitUnicodeString(&finishEventName, L"\\BaseNamedObjects\\" SYNC_EVENT_NAME L"2");

    InitializeObjectAttributes(&incoming_obj_attr, &incomingEventName, OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&finish_obj_attr, &finishEventName, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenEvent(&incomingEventHandle, EVENT_ALL_ACCESS, &incoming_obj_attr);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ZwOpenEvent 1. 0x%x\n", status); return; }

    status = ZwOpenEvent(&finishEventHandle, EVENT_ALL_ACCESS, &finish_obj_attr);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ZwOpenEvent 2. 0x%x\n", status); return; }
    
    status = ObReferenceObjectByHandle(incomingEventHandle, GENERIC_ALL, *ExEventObjectType, KernelMode, (VOID**)&incomingEvent, NULL);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ObReferenceObjectByHandle 1. 0x%x\n", status); return; }

    status = ObReferenceObjectByHandle(finishEventHandle, GENERIC_ALL, *ExEventObjectType, KernelMode, (VOID**)&finishEvent, NULL);
    if (!NT_SUCCESS(status)) { DbgPrintEx(0, 0, "Failed in ObReferenceObjectByHandle 2. 0x%x\n", status); return; }


    /*  FROM MSDN:
    Callers of KeWaitForMutexObject must be running at IRQL <= DISPATCH_LEVEL. 
    However, if Timeout = NULL or *Timeout != 0, the caller must be running at IRQL <= APC_LEVEL and in a nonarbitrary thread context. 
    (If Timeout != NULL and *Timeout = 0, the caller must be running at IRQL <= DISPATCH_LEVEL.)
    */
    // the stub is at passive level yet runs in an arbitrary thread
    LARGE_INTEGER wait_time = { .QuadPart = -50000000 };    // unit: 100 nanosec, = 5 sec

    while (TRUE)
    {
        // wait 
        if (STATUS_TIMEOUT != KeWaitForSingleObject(incomingEvent, Executive, KernelMode, FALSE, &wait_time))
        {
            if (strstr((const char*)sharedMemory, "exit")) break;
            // parse and dispatch here
            //MMapDispatch(sharedMemory);
            PMMAP_IO_REQUEST ioreq = (PMMAP_IO_REQUEST)sharedMemory;
            ULONG BytesIO;
            DoIoControl(ioreq->ControlCode, &ioreq->SystemBuffer, &BytesIO);
            KeSetEvent(finishEvent, 1, FALSE);
        }
    }

    ObDereferenceObject(incomingEvent);
    ObDereferenceObject(finishEvent);
    ZwClose(incomingEventHandle);
    ZwClose(finishEventHandle);

    ZwUnmapViewOfSection((HANDLE)ZwCurrentProcess(), sharedMemory);
    ZwClose(sectionHandle);
    ZwClose(mmapThreadHandle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    // init
    pDeviceObject = NULL;
    TargetPid = NULL;
    TargetBaseAddress = NULL;
    ProcessCache = NULL;
    RtlZeroMemory(CaptureModuleName, 512*sizeof(WCHAR));

    DbgPrintEx(0, 0, "Driver Running\n");

	PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    // mmap compatibility
    if (!pDriverObject || !pRegistryPath)
    {
        PsCreateSystemThread(&mmapThreadHandle, GENERIC_ALL, NULL, NULL, NULL, SetupMMapIo, NULL);
        return STATUS_SUCCESS;
    }

	RtlInitUnicodeString(&dev, L"\\Device\\" DRIVER_DEVICE_NAME);
	RtlInitUnicodeString(&dos, L"\\DosDevices\\" DRIVER_DEVICE_NAME);

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}


