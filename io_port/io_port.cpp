#include <Windows.h>
#include <iostream>

#define IOCTL_READ_IO_PORT  0x80102050
#define IOCTL_WRITE_IO_PORT 0x80102054

#pragma pack(push, 1)
struct port_read_request
{
    unsigned short port;
    unsigned short pad0;
    unsigned short pad1;
    char size;
};

struct port_write_request
{
    unsigned short port;
    unsigned int value;
    char size;
};
#pragma pack(pop)

int main()
{

    HANDLE driver_handle = CreateFileW(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, 3, nullptr, 3, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (driver_handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to grab driver handle.\n";
        std::cin.get();
        return 1;
    }

    std::cout << "Grabbed driver handle.\n\n";

    // Bit 31: Enable Bit (Must be 1)
    // Bits 23-16: Bus Number (0)
    // Bits 15-11: Device Number (0)
    // Bits 10-8: Function Number (0)
    // Bits 7-2: Register Offset (0x00 for Vendor/Device ID)
    // Result: 0x80000000
    unsigned int pci_address = 0x80000000;

    port_write_request write_req = { 0xCF8, pci_address, 4 }; // CONFIG_ADDRESS
    DWORD bytes = 0;

    if (!DeviceIoControl(driver_handle, IOCTL_WRITE_IO_PORT, &write_req, sizeof(port_write_request), nullptr, 0, &bytes, nullptr))
    {
        std::cout << "Failed to write to 0xCF8.\n";
        CloseHandle(driver_handle);
        return 1;
    }

    port_read_request read_req = { 0xCFC, 0, 0, 4 }; // CONFIG_DATA
    DWORD pci_data = 0;

    if (!DeviceIoControl(driver_handle, IOCTL_READ_IO_PORT, &read_req, sizeof(port_read_request), &pci_data, sizeof(DWORD), &bytes, nullptr))
    {
        std::cout << "Failed to read from 0xCFC.\n";
        CloseHandle(driver_handle);
        return 1;
    }

    unsigned short vendor_id = pci_data & 0xFFFF;
    unsigned short device_id = (pci_data >> 16) & 0xFFFF;

    std::cout << "Successfully read Bus 0, Device 0, Function 0\n\n";
    std::cout << "Raw 32-bit data: 0x" << std::hex << pci_data << "\n";
    std::cout << "Vendor ID: 0x" << std::hex << vendor_id << "\n";
    std::cout << "Device ID: 0x" << std::hex << device_id << "\n\n";

    if (vendor_id == 0x8086)
        std::cout << "Intel chipset detected.\n";
    else if (vendor_id == 0x1022)
        std::cout << "AMD chipset detected.\n";
    else
        std::cout << "Unknown vendor.\n";

    std::cout << "Press enter to exit.";

    CloseHandle(driver_handle);
    std::cin.get();
    return 0;
}