# LiesGate: Advanced Shellcode Injection Technique

## Introduction

LiesGate is a sophisticated shellcode injection technique that leverages Hell's Gate to dynamically find syscall numbers, modifies system calls, and uses thread hijacking to inject and execute shellcode within a target process. This technique is designed to evade detection and bypass security mechanisms by dynamically resolving syscall numbers and executing shellcode in the context of existing threads.

## PhantomGate: Enhanced LiesGate Technique

PhantomGate is an improvement over LiesGate, adding the ability to dynamically modify functions to use different syscall numbers, set hardware breakpoints, and update registers. This enhanced method provides additional stealth and flexibility, making it even more effective in evading detection.

## Features

- **Dynamic Syscall Resolution (Hell's Gate)**: Finds syscall numbers dynamically by analyzing function bytes in `ntdll.dll`.
- **Function Modification**: Modifies functions to use different syscall numbers.
- **Thread Hijacking**: Suspends and resumes threads to execute shellcode.
- **Hardware Breakpoints**: Sets hardware breakpoints on functions for additional control.
- **Register Updates**: Updates registers and continues execution seamlessly.

## Requirements

- Windows OS
- Visual Studio or a compatible C++ compiler
- Administrative privileges for process and thread manipulation

## How It Works

1. **Dynamic Syscall Resolution**: The `FindSyscallNumber` function parses the bytes of a function in `ntdll.dll` to find the syscall number.
2. **Function Modification**: The `ModifyFunctionToSyscall` function modifies the first few bytes of a function to directly invoke a syscall with a specified syscall number.
3. **Loading Shellcode**: Shellcode is read from a binary file and written into the target process's memory.
4. **Memory Protection**: Changes the memory protection of the allocated shellcode region to `PAGE_EXECUTE_READ`.
5. **Thread Hijacking**: Takes a snapshot of the target process's threads, finds a thread, suspends it, modifies its context to point to the shellcode, and resumes it.
6. **Hardware Breakpoints**: Sets a hardware breakpoint on the modified function for additional control.

## Usage

1. **Compile the Code**: Use Visual Studio or a compatible C++ compiler to compile the code.
2. **Run the Program**: Execute the compiled binary with administrative privileges, specifying the target process ID and the shellcode file.

## License

This project is licensed under the MIT License.
