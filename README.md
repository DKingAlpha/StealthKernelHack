# StealthKernelHack

A kernel mode toolset that reads/writes memory in a stealthy way, with compatibility for **manual mapped driver**.

The mainly advantage of this project is the ability to interact with your unsigned driver in any x64 ststem.

### Details
By implementing a simple communicating protocol based on File Mapping (mem mapping to be exact) and Event notifying, this project supports kernelmode-usermode interaction with mmaped driver.

To load your unsiged driver without changing system setting, search with keyword `drvmap`

### Usage
1. Edit `Driver/Driver.h`, edit `StealthKernelHack/StealthKernelHack.cpp`. compile both projects.
2. Run StealthKernelHack.exe first
3. Find a way to load the driver in your system. If you cannot sign your driver, find a way to mmap it into kernel space.
4. Use DriverHelper in StealthKernelHack codes to interact with driver.

### Feature
* Stealth Operations
* Get a process handle without a ring3 API
* Read/Write Process Memory without sensitive ring0 API.
* DeviceIoControl Alternative for Manual Mapped Driver Compatibility

### Known issues
PatchGuard will find the driver injection in around 5 to 30 minutes then BSOD.

### Credit:
Some basic codes from [Zer0Mem0ry/KernelBhop](https://github.com/Zer0Mem0ry/KernelBhop)
