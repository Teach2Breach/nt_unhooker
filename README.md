# NT(dll) Unhooker

A Windows security tool demonstrating a method to detect and remove inline hooks and IAT (Import Address Table) hooks from NTDLL.dll. This tool is particularly useful for security researchers, penetration testers, and malware analysts who need to restore the integrity of system DLLs that may have been hooked by security solutions or malicious software.

## Features

- **Inline Hook Detection**: Identifies and removes inline hooks in NTDLL.dll functions
- **IAT Hook Detection**: Detects and cleans Import Address Table hooks
- **Clean NTDLL Restoration**: Downloads and uses a clean version of NTDLL for comparison
- **Critical Function Protection**: Safely skips critical functions to prevent system instability

## How It Works

The tool works by:

1. **Loading NTDLL**: Dynamically loads NTDLL.dll using Windows API functions
2. **PE Analysis**: Parses the PE headers to extract function information
3. **Clean Comparison**: Downloads a clean version of NTDLL for comparison
4. **Hook Detection**: Compares the current NTDLL with the clean version to identify hooks
5. **Unhooking**: Restores original function code by overwriting hooked functions
6. **IAT Cleaning**: Removes any IAT hooks that redirect function calls

## Prerequisites

- Rust toolchain (latest stable version)
- Windows development environment

## Installation

```bash
# For development
cargo build

# For release (recommended)
cargo build --release

# For static linking
cargo rustc --release --bin nt_unhooker -- -C target-feature=+crt-static
```

## Example Output

When the tool runs successfully, you'll see output similar to this (truncated):

```
String length: 18, Maximum length: 20
Buffer contents: [110, 116, 100, 108, 108, 46, 100, 108, 108, 0]
Attempting download from: https://msdl.microsoft.com/download/symbols/ntdll.dll/67CA8829217000/ntdll.dll
Successfully downloaded clean NTDLL: 2187376 bytes
Starting unhooking process...
Getting NTDLL handle...
NTDLL handle obtained: 0x7ffb28710000

Checking current hook status:

[Inline Hooks]
NtMapViewOfSection: 4C 8B D1 E9 C6 E8 08 00 F6 04 25 08 03 FE 7F 01  [HOOKED]
NtProtectVirtualMemory: 4C 8B D1 E9 BF E3 08 00 F6 04 25 08 03 FE 7F 01  [HOOKED]
NtWriteVirtualMemory: 4C 8B D1 E9 7D E6 08 00 F6 04 25 08 03 FE 7F 01  [HOOKED]
NtAllocateVirtualMemory: 4C 8B D1 E9 C0 EA 08 00 F6 04 25 08 03 FE 7F 01  [HOOKED]

[IAT Hooks]
NtCreateFile: 4C 8B D1 B8 55 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]

Unhooking operations:
Starting inline hook removal...
Processing sections...
Processing section: .text
Found .text section at RVA: 0x1000, Raw offset: 0x1000, Size: 0x12e000
Writing clean section at 0x7ffb28711000 with size 0x12e000
Successfully wrote 1236992 bytes
✓ Inline hooks removed
Starting IAT hook removal...
✓ IAT hooks removed

Verifying final state:

[Inline Hooks]
NtMapViewOfSection: 4C 8B D1 B8 28 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]
NtProtectVirtualMemory: 4C 8B D1 B8 50 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]
NtWriteVirtualMemory: 4C 8B D1 B8 3A 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]
NtAllocateVirtualMemory: 4C 8B D1 B8 18 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]

[IAT Hooks]
NtCreateFile: 4C 8B D1 B8 55 00 00 00 F6 04 25 08 03 FE 7F 01  [CLEAN]

Successfully completed all unhooking operations
Successfully unhooked all hooks
```

This example shows the tool successfully detecting and removing inline hooks from several critical NTDLL functions while leaving clean functions untouched.
